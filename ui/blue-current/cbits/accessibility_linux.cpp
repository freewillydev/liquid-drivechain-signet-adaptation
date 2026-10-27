#include "accessibility_shared.hpp"
#include <atk/atk.h>
#include <atk-bridge.h>
#include <map>
#include <algorithm>

// ATK's D-Bus adaptor exposes this tree to AT-SPI clients (including Orca).
// ATK objects and notifications belong exclusively to this GLib thread.
struct BCNode {AtkObject parent;BCItem* item;bool present;GPtrArray* children;};
struct BCNodeClass {AtkObjectClass parent;};
static AtkObject* appRoot;
static AtkObject* frame;
static std::map<std::string,BCNode*> leaves;
static GMainLoop* bridgeLoop;
static gsize started;
static std::mutex snapshotMutex;
static std::vector<BCItem> latest;
static bool snapshotReady;
static int originX,originY,windowWidth=1,windowHeight=1;
static int pendingX,pendingY,pendingWidth=1,pendingHeight=1;
static bool pendingActive,windowActive;

static void componentInit(AtkComponentIface*);
static void actionInit(AtkActionIface*);
static void textInit(AtkTextIface*);
static void editableInit(AtkEditableTextIface*);
G_DEFINE_TYPE_WITH_CODE(BCNode,bc_node,ATK_TYPE_OBJECT,
  G_IMPLEMENT_INTERFACE(ATK_TYPE_COMPONENT,componentInit)
  G_IMPLEMENT_INTERFACE(ATK_TYPE_ACTION,actionInit)
  G_IMPLEMENT_INTERFACE(ATK_TYPE_TEXT,textInit)
  G_IMPLEMENT_INTERFACE(ATK_TYPE_EDITABLE_TEXT,editableInit))

static BCNode* node(gpointer p){return reinterpret_cast<BCNode*>(p);}
static int childCount(AtkObject* p){return node(p)->children?node(p)->children->len:0;}
static AtkObject* childAt(AtkObject* p,int index){auto* a=node(p)->children;return a&&index>=0&&index<int(a->len)?ATK_OBJECT(g_object_ref(g_ptr_array_index(a,index))):nullptr;}
static int indexInParent(AtkObject* p){auto* parent=atk_object_get_parent(p);if(!parent)return -1;auto* a=node(parent)->children;for(guint i=0;a&&i<a->len;i++)if(g_ptr_array_index(a,i)==p)return i;return -1;}
static void extents(AtkComponent* p,int* x,int* y,int* w,int* h,AtkCoordType coords){
  auto* n=node(p);auto& i=*n->item;
  *x=int(i.x)+(coords==ATK_XY_SCREEN?originX:0);*y=int(i.y)+(coords==ATK_XY_SCREEN?originY:0);*w=int(i.w);*h=int(i.h);
  if(ATK_OBJECT(p)==frame||ATK_OBJECT(p)==appRoot){*x=coords==ATK_XY_SCREEN?originX:0;*y=coords==ATK_XY_SCREEN?originY:0;*w=windowWidth;*h=windowHeight;}
}
static bool showing(BCNode* n){auto& i=*n->item;return n->present&&i.w>0&&i.h>0&&i.x+i.w>0&&i.y+i.h>0&&i.x<windowWidth&&i.y<windowHeight;}
static AtkStateSet* states(AtkObject* p){
  auto* n=node(p);auto& i=*n->item;auto* s=atk_state_set_new();
  if(!n->present){atk_state_set_add_state(s,ATK_STATE_DEFUNCT);return s;}
  atk_state_set_add_state(s,ATK_STATE_VISIBLE);
  if(p==appRoot||p==frame||showing(n))atk_state_set_add_state(s,ATK_STATE_SHOWING);
  if(i.enabled){atk_state_set_add_state(s,ATK_STATE_ENABLED);atk_state_set_add_state(s,ATK_STATE_SENSITIVE);}
  if(i.kind=="button"||i.kind=="field")atk_state_set_add_state(s,ATK_STATE_FOCUSABLE);
  if(i.kind=="field"){atk_state_set_add_state(s,ATK_STATE_SINGLE_LINE);if(i.enabled)atk_state_set_add_state(s,ATK_STATE_EDITABLE);}
  if(i.focused&&windowActive)atk_state_set_add_state(s,ATK_STATE_FOCUSED);
  if(p==frame&&windowActive)atk_state_set_add_state(s,ATK_STATE_ACTIVE);
  return s;
}
static void finalize(GObject* p){auto* n=node(p);delete n->item;if(n->children)g_ptr_array_unref(n->children);G_OBJECT_CLASS(bc_node_parent_class)->finalize(p);}
static AtkAttributeSet* attributes(AtkObject* p){
  auto* n=node(p);AtkAttributeSet* out=nullptr;
  auto attr=[&](const char* name,const std::string& value){auto* a=g_new0(AtkAttribute,1);a->name=g_strdup(name);a->value=g_strdup(value.c_str());out=g_slist_append(out,a);};
  attr("id",n->item->key);attr("toolkit","Monomer");
  if(n->item->key=="notice"||n->item->key=="panel-title"){attr("live","assertive");attr("atomic","true");attr("container-live","assertive");}
  return out;
}
static void bc_node_class_init(BCNodeClass* klass){
  auto* c=ATK_OBJECT_CLASS(klass);c->get_n_children=childCount;c->ref_child=childAt;c->get_index_in_parent=indexInParent;c->ref_state_set=states;c->get_attributes=attributes;
  G_OBJECT_CLASS(klass)->finalize=finalize;
}
static void bc_node_init(BCNode* n){n->item=new BCItem{};n->present=true;n->children=g_ptr_array_new_with_free_func(g_object_unref);}
static BCNode* makeNode(const BCItem& item,AtkRole role,AtkObject* parent){
  auto* n=node(g_object_new(bc_node_get_type(),nullptr));*n->item=item;
  atk_object_set_role(ATK_OBJECT(n),role);atk_object_set_name(ATK_OBJECT(n),item.label.c_str());atk_object_set_parent(ATK_OBJECT(n),parent);return n;
}
static gboolean grabFocus(AtkComponent* p){auto* n=node(p);if(!n->present||!n->item->enabled)return false;enqueue("focus:"+n->item->key);return true;}
static gboolean contains(AtkComponent* p,int x,int y,AtkCoordType c){int px,py,w,h;extents(p,&px,&py,&w,&h,c);return x>=px&&y>=py&&x<px+w&&y<py+h;}
static AtkObject* pointAt(AtkComponent* p,int x,int y,AtkCoordType c){auto* n=node(p);for(int i=int(n->children->len)-1;i>=0;i--){auto* child=ATK_OBJECT(g_ptr_array_index(n->children,i));if(contains(ATK_COMPONENT(child),x,y,c))return ATK_OBJECT(g_object_ref(child));}return nullptr;}
static AtkLayer layer(AtkComponent*){return ATK_LAYER_WIDGET;}
static void componentInit(AtkComponentIface* i){i->get_extents=extents;i->grab_focus=grabFocus;i->contains=contains;i->ref_accessible_at_point=pointAt;i->get_layer=layer;}
static int nActions(AtkAction* p){auto& i=*node(p)->item;return i.kind=="button"||i.kind=="field"?1:0;}
static gboolean doAction(AtkAction* p,int index){auto* n=node(p);if(index!=0||!n->present||!n->item->enabled||!nActions(p))return false;enqueue(n->item->kind=="field"?"focus:"+n->item->key:n->item->key);return true;}
static const gchar* actionName(AtkAction* p,int index){return index==0&&nActions(p)?(node(p)->item->kind=="field"?"focus":"click"):nullptr;}
static const gchar* actionDescription(AtkAction* p,int index){return index==0&&nActions(p)?node(p)->item->label.c_str():nullptr;}
static const gchar* keyBinding(AtkAction*,int){return "";}
static void actionInit(AtkActionIface* i){i->get_n_actions=nActions;i->do_action=doAction;i->get_name=actionName;i->get_localized_name=actionName;i->get_description=actionDescription;i->get_keybinding=keyBinding;}
static std::string textValue(gpointer p){return node(p)->item->value;}
static gchar* getText(AtkText* p,int start,int end){auto value=textValue(p);auto length=g_utf8_strlen(value.c_str(),-1);start=std::max(0,std::min(start,int(length)));end=end<0?length:std::max(start,std::min(end,int(length)));return g_utf8_substring(value.c_str(),start,end);}
static gunichar characterAt(AtkText* p,int index){auto value=textValue(p);return index>=0&&index<g_utf8_strlen(value.c_str(),-1)?g_utf8_get_char(g_utf8_offset_to_pointer(value.c_str(),index)):0;}
static int characterCount(AtkText* p){return g_utf8_strlen(node(p)->item->value.c_str(),-1);}
static int caret(AtkText* p){return characterCount(p);}
static gboolean setCaret(AtkText* p,int){return grabFocus(ATK_COMPONENT(p));}
static int selectionCount(AtkText*){return 0;}
static AtkAttributeSet* defaultTextAttrs(AtkText*){return nullptr;}
static gchar* stringAt(AtkText* p,int offset,AtkTextGranularity granularity,int* start,int* end){
  auto value=textValue(p);int count=characterCount(p);offset=std::max(0,std::min(offset,count));*start=0;*end=count;
  if(granularity==ATK_TEXT_GRANULARITY_CHAR){*start=offset;*end=std::min(offset+1,count);}
  else if(granularity==ATK_TEXT_GRANULARITY_WORD){*start=offset;*end=offset;while(*start>0&&!g_unichar_isspace(characterAt(p,*start-1)))--*start;while(*end<count&&!g_unichar_isspace(characterAt(p,*end)))++*end;}
  return getText(p,*start,*end);
}
static void textExtents(AtkText* p,int,int* x,int* y,int* w,int* h,AtkCoordType c){extents(ATK_COMPONENT(p),x,y,w,h,c);}
static void textInit(AtkTextIface* i){i->get_text=getText;i->get_character_at_offset=characterAt;i->get_character_count=characterCount;i->get_caret_offset=caret;i->set_caret_offset=setCaret;i->get_n_selections=selectionCount;i->get_default_attributes=defaultTextAttrs;i->get_string_at_offset=stringAt;i->get_character_extents=textExtents;}
static void setContents(AtkEditableText* p,const gchar* value){auto* n=node(p);if(n->present&&n->item->enabled&&n->item->kind=="field")enqueue(n->item->key,value?value:"");}
static void insertText(AtkEditableText* p,const gchar* text,int length,int* position){auto* n=node(p);auto value=textValue(p);int pos=std::max(0,std::min(*position,int(g_utf8_strlen(value.c_str(),-1))));auto byte=g_utf8_offset_to_pointer(value.c_str(),pos)-value.c_str();auto addition=std::string(text,length<0?strlen(text):size_t(length));value.insert(byte,addition);setContents(p,value.c_str());*position=pos+g_utf8_strlen(addition.c_str(),-1);}
static void deleteText(AtkEditableText* p,int start,int end){auto value=textValue(p);int length=g_utf8_strlen(value.c_str(),-1);start=std::max(0,std::min(start,length));end=std::max(start,std::min(end,length));auto begin=g_utf8_offset_to_pointer(value.c_str(),start)-value.c_str();auto finish=g_utf8_offset_to_pointer(value.c_str(),end)-value.c_str();value.erase(begin,finish-begin);setContents(p,value.c_str());}
static void editableInit(AtkEditableTextIface* i){i->set_text_contents=setContents;i->insert_text=insertText;i->delete_text=deleteText;}
static AtkObject* getRoot(){return appRoot;}
static const gchar* toolkit(){return "Monomer";}
static const gchar* version(){return "1.6.0.1";}
static gboolean applySnapshot(gpointer){
  std::vector<BCItem> items;bool wasActive=windowActive;
  {std::lock_guard<std::mutex> lock(snapshotMutex);if(!snapshotReady)return G_SOURCE_CONTINUE;items=latest;windowActive=pendingActive;originX=pendingX;originY=pendingY;windowWidth=pendingWidth;windowHeight=pendingHeight;snapshotReady=false;}
  if(wasActive!=windowActive)atk_object_notify_state_change(frame,ATK_STATE_ACTIVE,windowActive);
  std::vector<std::string> before;for(guint i=0;i<node(frame)->children->len;i++)before.push_back(node(g_ptr_array_index(node(frame)->children,i))->item->key);
  std::vector<std::string> after;for(auto& i:items)after.push_back(i.key);
  bool structure=before!=after;
  if(structure){
    for(int i=int(node(frame)->children->len)-1;i>=0;i--){auto* child=ATK_OBJECT(g_ptr_array_index(node(frame)->children,i));g_signal_emit_by_name(frame,"children-changed::remove",i,child,nullptr);}
    g_ptr_array_set_size(node(frame)->children,0);
  }
  for(auto& p:leaves)p.second->present=false;
  for(auto& item:items){
    BCNode* n;auto it=leaves.find(item.key);bool fresh=it==leaves.end();
    if(fresh){n=makeNode(item,item.kind=="button"?ATK_ROLE_PUSH_BUTTON:item.kind=="field"?ATK_ROLE_ENTRY:item.key=="notice"?ATK_ROLE_ALERT:ATK_ROLE_STATIC,frame);leaves[item.key]=n;}else n=it->second;
    auto old=*n->item;if(fresh){old.value="";old.focused=false;}*n->item=item;n->present=true;
    std::string name=item.label+(item.kind=="text"&&!item.value.empty()?": "+item.value:"");atk_object_set_name(ATK_OBJECT(n),name.c_str());
    if(old.value!=item.value){
      *n->item=old;g_signal_emit_by_name(n,"text-changed::delete",0,int(g_utf8_strlen(old.value.c_str(),-1)));*n->item=item;
      g_signal_emit_by_name(n,"text-changed::insert",0,int(g_utf8_strlen(item.value.c_str(),-1)));
      if(item.key=="notice"||item.key=="panel-title")g_signal_emit_by_name(n,"announcement",item.value.c_str(),ATK_LIVE_ASSERTIVE);
    }
    if(old.enabled!=item.enabled){atk_object_notify_state_change(ATK_OBJECT(n),ATK_STATE_ENABLED,item.enabled);atk_object_notify_state_change(ATK_OBJECT(n),ATK_STATE_SENSITIVE,item.enabled);}
    if(old.focused!=item.focused){atk_object_notify_state_change(ATK_OBJECT(n),ATK_STATE_FOCUSED,item.focused);}
    if(structure)g_ptr_array_add(node(frame)->children,g_object_ref(n));
  }
  for(auto it=leaves.begin();it!=leaves.end();)if(!it->second->present){atk_object_notify_state_change(ATK_OBJECT(it->second),ATK_STATE_DEFUNCT,true);atk_object_set_parent(ATK_OBJECT(it->second),nullptr);g_object_unref(it->second);it=leaves.erase(it);}else ++it;
  if(structure)for(guint i=0;i<node(frame)->children->len;i++)g_signal_emit_by_name(frame,"children-changed::add",i,g_ptr_array_index(node(frame)->children,i),nullptr);
  return G_SOURCE_CONTINUE;
}
static gpointer bridgeThread(gpointer){
  appRoot=ATK_OBJECT(makeNode({"application","Elements Blue Current","root","",true,false,0,0,0,0},ATK_ROLE_APPLICATION,nullptr));
  frame=ATK_OBJECT(makeNode({"wallet-root","Elements wallet","root","",true,false,0,0,0,0},ATK_ROLE_FRAME,appRoot));g_ptr_array_add(node(appRoot)->children,g_object_ref(frame));
  auto* util=ATK_UTIL_CLASS(g_type_class_ref(ATK_TYPE_UTIL));util->get_root=getRoot;util->get_toolkit_name=toolkit;util->get_toolkit_version=version;
  atk_bridge_adaptor_init(nullptr,nullptr);
  bridgeLoop=g_main_loop_new(nullptr,false);g_timeout_add(50,applySnapshot,nullptr);g_main_loop_run(bridgeLoop);return nullptr;
}
extern "C" void bc_ax_end(){
  auto* win=appWindow();if(!win)return;
  int x,y,w,h;SDL_GetWindowPosition(win,&x,&y);SDL_GetWindowSize(win,&w,&h);SDL_SetWindowMinimumSize(win,320,400);
  {std::lock_guard<std::mutex> lock(snapshotMutex);pendingActive=(SDL_GetWindowFlags(win)&SDL_WINDOW_INPUT_FOCUS)!=0;pendingX=x;pendingY=y;pendingWidth=w;pendingHeight=h;latest=incoming;snapshotReady=true;}
  if(g_once_init_enter(&started)){g_thread_new("wallet-at-spi",bridgeThread,nullptr);g_once_init_leave(&started,1);}
}
