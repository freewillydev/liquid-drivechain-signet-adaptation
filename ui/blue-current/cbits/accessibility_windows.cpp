#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <ole2.h>
#include <uiautomation.h>
#include "uia_compat.hpp"
#include <tlhelp32.h>
#include <algorithm>
#include <map>
#include <cstdio>
#include "accessibility_shared.hpp"

// Native server-side UI Automation providers for Monomer's drawn controls.
// All UI mutations are queued back to Haskell, never performed in a COM callback.
static std::recursive_mutex treeMutex;
static HWND windowHandle;
static WNDPROC originalProc;
static int nextId=1;
static constexpr UINT captureMessage=WM_APP+0xBC;

// Opt-in QA captures read only this application's OpenGL front buffer. GDI
// screenshots can omit AMD hardware-overlay surfaces on Windows 11.
static void captureFrame(const std::string& path) {
  auto library=LoadLibraryExW(L"opengl32.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
  auto context=reinterpret_cast<HGLRC (WINAPI*)()>(GetProcAddress(library,"wglGetCurrentContext"));
  auto get=reinterpret_cast<void (WINAPI*)(unsigned,int*)>(GetProcAddress(library,"glGetIntegerv"));
  auto read=reinterpret_cast<void (WINAPI*)(int,int,int,int,unsigned,unsigned,void*)>(GetProcAddress(library,"glReadPixels"));
  auto buffer=reinterpret_cast<void (WINAPI*)(unsigned)>(GetProcAddress(library,"glReadBuffer"));
  auto finish=reinterpret_cast<void (WINAPI*)()>(GetProcAddress(library,"glFinish"));
  if(!context||!context()||!get||!read||!buffer||!finish)return;
  int viewport[4]{},previous;get(0x0BA2,viewport);get(0x0C02,&previous);
  int width=viewport[2],height=viewport[3];if(width<1||height<1||width>8000||height>8000)return;
  std::vector<unsigned char> pixels(size_t(width)*height*4);
  finish();buffer(0x0404);read(0,0,width,height,0x1908,0x1401,pixels.data());buffer(previous);
  for(size_t i=0;i<pixels.size();i+=4)std::swap(pixels[i],pixels[i+2]);
  BITMAPFILEHEADER file{};file.bfType=0x4d42;file.bfOffBits=sizeof(file)+sizeof(BITMAPINFOHEADER);file.bfSize=file.bfOffBits+pixels.size();
  BITMAPINFOHEADER info{};info.biSize=sizeof(info);info.biWidth=width;info.biHeight=height;info.biPlanes=1;info.biBitCount=32;
  if(auto* out=std::fopen(path.c_str(),"wb")){std::fwrite(&file,1,sizeof(file),out);std::fwrite(&info,1,sizeof(info),out);std::fwrite(pixels.data(),1,pixels.size(),out);std::fclose(out);}
}
// GHC ships the SDK headers but no UIAutomation import library. Resolve the OS API.
static decltype(&UiaReturnRawElementProvider) apiUiaReturnRawElementProvider;
static decltype(&UiaHostProviderFromHwnd) apiUiaHostProviderFromHwnd;
static HRESULT (WINAPI *apiUiaRaiseStructureChangedEvent)(IRawElementProviderSimple*,int,int*,int);
static HRESULT (WINAPI *apiUiaRaiseAutomationPropertyChangedEvent)(IRawElementProviderSimple*,int,VARIANT,VARIANT);
static decltype(&UiaRaiseAutomationEvent) apiUiaRaiseAutomationEvent;
static bool loadAutomation(){
  auto library=LoadLibraryExW(L"UIAutomationCore.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
  if(!library)return false;
  apiUiaReturnRawElementProvider=reinterpret_cast<decltype(apiUiaReturnRawElementProvider)>(GetProcAddress(library,"UiaReturnRawElementProvider"));
  apiUiaHostProviderFromHwnd=reinterpret_cast<decltype(apiUiaHostProviderFromHwnd)>(GetProcAddress(library,"UiaHostProviderFromHwnd"));
  apiUiaRaiseStructureChangedEvent=reinterpret_cast<decltype(apiUiaRaiseStructureChangedEvent)>(GetProcAddress(library,"UiaRaiseStructureChangedEvent"));
  apiUiaRaiseAutomationPropertyChangedEvent=reinterpret_cast<decltype(apiUiaRaiseAutomationPropertyChangedEvent)>(GetProcAddress(library,"UiaRaiseAutomationPropertyChangedEvent"));
  apiUiaRaiseAutomationEvent=reinterpret_cast<decltype(apiUiaRaiseAutomationEvent)>(GetProcAddress(library,"UiaRaiseAutomationEvent"));
  return apiUiaReturnRawElementProvider&&apiUiaHostProviderFromHwnd&&apiUiaRaiseStructureChangedEvent&&apiUiaRaiseAutomationPropertyChangedEvent&&apiUiaRaiseAutomationEvent;
}
#define UiaReturnRawElementProvider apiUiaReturnRawElementProvider
#define UiaHostProviderFromHwnd apiUiaHostProviderFromHwnd
#define UiaRaiseStructureChangedEvent apiUiaRaiseStructureChangedEvent
#define UiaRaiseAutomationPropertyChangedEvent apiUiaRaiseAutomationPropertyChangedEvent
#define UiaRaiseAutomationEvent apiUiaRaiseAutomationEvent

static std::wstring wide(const std::string& s) {
  int n=MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,nullptr,0);
  std::wstring out(n,0);MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,&out[0],n);
  if(!out.empty())out.pop_back();return out;
}
static std::string utf8(LPCWSTR s) {
  if(!s)return "";
  int n=WideCharToMultiByte(CP_UTF8,0,s,-1,nullptr,0,nullptr,nullptr);
  std::string out(n,0);WideCharToMultiByte(CP_UTF8,0,s,-1,&out[0],n,nullptr,nullptr);
  if(!out.empty())out.pop_back();return out;
}
class Provider;
static Provider* rootProvider;
static std::vector<Provider*> children;
static std::map<std::string,Provider*> byKey;
class Provider : public IRawElementProviderSimple, public IRawElementProviderFragment, public IRawElementProviderFragmentRoot,
                 public IInvokeProvider, public IValueProvider {
  LONG refs=1;
 public:
  BCItem item;
  bool root, present=true;
  int id;
  Provider(bool isRoot,const BCItem& data):item(data),root(isRoot),id(nextId++){}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);
    if(!out)return E_POINTER;*out=nullptr;
    if(iid==__uuidof(IUnknown)||iid==__uuidof(IRawElementProviderSimple)) *out=static_cast<IRawElementProviderSimple*>(this);
    else if(iid==__uuidof(IRawElementProviderFragment)) *out=static_cast<IRawElementProviderFragment*>(this);
    else if(iid==__uuidof(IRawElementProviderFragmentRoot)&&root) *out=static_cast<IRawElementProviderFragmentRoot*>(this);
    else if(iid==__uuidof(IInvokeProvider)&&item.kind=="button") *out=static_cast<IInvokeProvider*>(this);
    else if(iid==__uuidof(IValueProvider)&&item.kind=="field") *out=static_cast<IValueProvider*>(this);
    else return E_NOINTERFACE;
    AddRef();return S_OK;
  }
  ULONG STDMETHODCALLTYPE AddRef() override {return InterlockedIncrement(&refs);}
  ULONG STDMETHODCALLTYPE Release() override {auto n=InterlockedDecrement(&refs);if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE get_ProviderOptions(ProviderOptions* out) override {*out=ProviderOptions_ServerSideProvider;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetPatternProvider(PATTERNID pattern,IUnknown** out) override {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);*out=nullptr;
    if(!present)return UIA_E_ELEMENTNOTAVAILABLE;
    if(pattern==UIA_InvokePatternId&&item.kind=="button")*out=static_cast<IInvokeProvider*>(this);
    if(pattern==UIA_ValuePatternId&&item.kind=="field")*out=static_cast<IValueProvider*>(this);
    if(*out)AddRef();return S_OK;
  }
  UiaRect bounds() {
    RECT r{};GetClientRect(windowHandle,&r);POINT origin{0,0};ClientToScreen(windowHandle,&origin);
    if(root)return {double(origin.x),double(origin.y),double(r.right),double(r.bottom)};
    int w=1,h=1;if(auto* win=appWindow())SDL_GetWindowSize(win,&w,&h);
    double sx=double(r.right)/std::max(1,w),sy=double(r.bottom)/std::max(1,h);
    return {origin.x+item.x*sx,origin.y+item.y*sy,item.w*sx,item.h*sy};
  }
  bool offscreen() {
    if(!present||!IsWindowVisible(windowHandle)||IsIconic(windowHandle))return true;
    if(root)return false;
    auto r=bounds();auto parent=rootProvider->bounds();
    return r.width<=0||r.height<=0||r.left+r.width<=parent.left||r.top+r.height<=parent.top||r.left>=parent.left+parent.width||r.top>=parent.top+parent.height;
  }
  HRESULT STDMETHODCALLTYPE GetPropertyValue(PROPERTYID prop,VARIANT* out) override {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);VariantInit(out);
    if(!present)return UIA_E_ELEMENTNOTAVAILABLE;
    std::string text;
    switch(prop) {
      case UIA_NamePropertyId:text=item.label+(item.kind=="text"&&!item.value.empty()?": "+item.value:"");break;
      case UIA_AutomationIdPropertyId:text=item.key;break;
      case UIA_FrameworkIdPropertyId:text="Monomer";break;
      case UIA_ControlTypePropertyId:out->vt=VT_I4;out->lVal=root?UIA_PaneControlTypeId:item.kind=="button"?UIA_ButtonControlTypeId:item.kind=="field"?UIA_EditControlTypeId:UIA_TextControlTypeId;return S_OK;
      case UIA_IsControlElementPropertyId:case UIA_IsContentElementPropertyId:out->vt=VT_BOOL;out->boolVal=VARIANT_TRUE;return S_OK;
      case UIA_IsEnabledPropertyId:out->vt=VT_BOOL;out->boolVal=item.enabled?VARIANT_TRUE:VARIANT_FALSE;return S_OK;
      case UIA_HasKeyboardFocusPropertyId:out->vt=VT_BOOL;out->boolVal=item.focused?VARIANT_TRUE:VARIANT_FALSE;return S_OK;
      case UIA_IsKeyboardFocusablePropertyId:out->vt=VT_BOOL;out->boolVal=item.kind=="button"||item.kind=="field"?VARIANT_TRUE:VARIANT_FALSE;return S_OK;
      case UIA_IsOffscreenPropertyId:out->vt=VT_BOOL;out->boolVal=offscreen()?VARIANT_TRUE:VARIANT_FALSE;return S_OK;
      case UIA_LiveSettingPropertyId:out->vt=VT_I4;out->lVal=item.key=="notice"?2:item.key=="panel-title"?1:0;return S_OK;
      default:return S_OK;
    }
    out->vt=VT_BSTR;out->bstrVal=SysAllocString(wide(text).c_str());return S_OK;
  }
  HRESULT STDMETHODCALLTYPE get_HostRawElementProvider(IRawElementProviderSimple** out) override {
    *out=nullptr;return root?UiaHostProviderFromHwnd(windowHandle,out):S_OK;
  }
  HRESULT STDMETHODCALLTYPE Navigate(NavigateDirection direction,IRawElementProviderFragment** out) override {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);*out=nullptr;
    if(!present)return UIA_E_ELEMENTNOTAVAILABLE;
    Provider* target=nullptr;
    if(root) {if(!children.empty()&&direction==NavigateDirection_FirstChild)target=children.front();if(!children.empty()&&direction==NavigateDirection_LastChild)target=children.back();}
    else if(direction==NavigateDirection_Parent)target=rootProvider;
    else {auto it=std::find(children.begin(),children.end(),this);if(it!=children.end()) {if(direction==NavigateDirection_NextSibling&&it+1!=children.end())target=*(it+1);if(direction==NavigateDirection_PreviousSibling&&it!=children.begin())target=*(it-1);}}
    if(target){*out=static_cast<IRawElementProviderFragment*>(target);target->AddRef();}return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetRuntimeId(SAFEARRAY** out) override {
    int values[2]={UiaAppendRuntimeId,id};*out=SafeArrayCreateVector(VT_I4,0,2);
    for(LONG i=0;i<2;i++)SafeArrayPutElement(*out,&i,&values[i]);return S_OK;
  }
  HRESULT STDMETHODCALLTYPE get_BoundingRectangle(UiaRect* out) override {std::lock_guard<std::recursive_mutex> lock(treeMutex);*out=bounds();return present?S_OK:UIA_E_ELEMENTNOTAVAILABLE;}
  HRESULT STDMETHODCALLTYPE GetEmbeddedFragmentRoots(SAFEARRAY** out) override {*out=nullptr;return S_OK;}
  HRESULT STDMETHODCALLTYPE SetFocus() override {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);
    if(!present)return UIA_E_ELEMENTNOTAVAILABLE;if(!item.enabled)return UIA_E_ELEMENTNOTENABLED;
    if(!root)enqueue("focus:"+item.key);return S_OK;
  }
  HRESULT STDMETHODCALLTYPE get_FragmentRoot(IRawElementProviderFragmentRoot** out) override {*out=rootProvider;rootProvider->AddRef();return S_OK;}
  HRESULT STDMETHODCALLTYPE ElementProviderFromPoint(double x,double y,IRawElementProviderFragment** out) override {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);*out=nullptr;
    for(auto it=children.rbegin();it!=children.rend();++it){auto r=(*it)->bounds();if(!(*it)->offscreen()&&x>=r.left&&y>=r.top&&x<r.left+r.width&&y<r.top+r.height){*out=*it;(*it)->AddRef();return S_OK;}}
    *out=this;AddRef();return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetFocus(IRawElementProviderFragment** out) override {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);*out=nullptr;
    for(auto* c:children)if(c->item.focused){*out=c;c->AddRef();break;}return S_OK;
  }
  HRESULT STDMETHODCALLTYPE Invoke() override {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);
    if(!present)return UIA_E_ELEMENTNOTAVAILABLE;if(!item.enabled)return UIA_E_ELEMENTNOTENABLED;
    if(item.kind!="button")return UIA_E_NOTSUPPORTED;enqueue(item.key);return S_OK;
  }
  HRESULT STDMETHODCALLTYPE SetValue(LPCWSTR value) override {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);
    if(!present)return UIA_E_ELEMENTNOTAVAILABLE;if(!item.enabled)return UIA_E_ELEMENTNOTENABLED;
    if(item.kind!="field")return UIA_E_NOTSUPPORTED;enqueue(item.key,utf8(value));return S_OK;
  }
  HRESULT STDMETHODCALLTYPE get_Value(BSTR* out) override {std::lock_guard<std::recursive_mutex> lock(treeMutex);*out=SysAllocString(wide(item.value).c_str());return present?S_OK:UIA_E_ELEMENTNOTAVAILABLE;}
  HRESULT STDMETHODCALLTYPE get_IsReadOnly(BOOL* out) override {std::lock_guard<std::recursive_mutex> lock(treeMutex);*out=!item.enabled;return S_OK;}
};
static LRESULT CALLBACK bridgeProc(HWND hwnd,UINT message,WPARAM w,LPARAM l) {
  if(message==captureMessage){auto* path=reinterpret_cast<std::string*>(l);captureFrame(*path);delete path;return 0;}
  if(message==WM_GETOBJECT&&static_cast<LONG>(l)==UiaRootObjectId&&rootProvider)
    return UiaReturnRawElementProvider(hwnd,w,l,static_cast<IRawElementProviderSimple*>(rootProvider));
  if(message==WM_GETMINMAXINFO) {
    auto result=CallWindowProc(originalProc,hwnd,message,w,l);
    auto* limits=reinterpret_cast<MINMAXINFO*>(l);RECT r{0,0,320,400};
    AdjustWindowRectEx(&r,GetWindowLongPtr(hwnd,GWL_STYLE),FALSE,GetWindowLongPtr(hwnd,GWL_EXSTYLE));
    limits->ptMinTrackSize={r.right-r.left,r.bottom-r.top};return result;
  }
  return CallWindowProc(originalProc,hwnd,message,w,l);
}
static BOOL CALLBACK findWindow(HWND hwnd,LPARAM result) {
  char title[128]{};GetWindowTextA(hwnd,title,sizeof(title));
  if(std::strstr(title,"Blue Current")){*reinterpret_cast<HWND*>(result)=hwnd;return FALSE;}return TRUE;
}
static HWND ownWindow() {
  HWND found=nullptr;auto snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
  if(snapshot==INVALID_HANDLE_VALUE)return nullptr;
  THREADENTRY32 entry{};entry.dwSize=sizeof(entry);
  if(Thread32First(snapshot,&entry))do {if(entry.th32OwnerProcessID==GetCurrentProcessId())EnumThreadWindows(entry.th32ThreadID,findWindow,reinterpret_cast<LPARAM>(&found));}while(!found&&Thread32Next(snapshot,&entry));
  CloseHandle(snapshot);return found;
}
extern "C" void bc_ax_end() {
  struct ComScope {HRESULT result=CoInitializeEx(nullptr,COINIT_MULTITHREADED);~ComScope(){if(SUCCEEDED(result))CoUninitialize();}} com;
  if(!windowHandle) {
    auto* win=appWindow();if(!win||!loadAutomation())return;
    windowHandle=ownWindow();if(!windowHandle)return;
    rootProvider=new Provider(true,{"wallet-root","Elements wallet","root","",true,false,0,0,0,0});
    originalProc=reinterpret_cast<WNDPROC>(SetWindowLongPtr(windowHandle,GWLP_WNDPROC,reinterpret_cast<LONG_PTR>(bridgeProc)));
  }
  if(const char* request=std::getenv("BLUE_CURRENT_CAPTURE_REQUEST")) {
    if(auto* file=std::fopen(request,"rb")){char path[1024]{};auto size=std::fread(path,1,sizeof(path)-1,file);std::fclose(file);std::remove(request);
      if(size>0){auto* copy=new std::string(path,size);if(!PostMessage(windowHandle,captureMessage,0,reinterpret_cast<LPARAM>(copy)))delete copy;}
    }
  }
  struct Change {Provider* node;bool value,focus,enabled;std::string oldValue;bool oldEnabled;};
  std::vector<Change> changes;bool structure=false;
  {
    std::lock_guard<std::recursive_mutex> lock(treeMutex);
    auto previous=children;children.clear();
    for(auto& pair:byKey)pair.second->present=false;
    for(auto& item:incoming) {
      auto it=byKey.find(item.key);Provider* node;
      if(it==byKey.end()) {node=new Provider(false,item);byKey[item.key]=node;}
      else node=it->second;
      bool fresh=it==byKey.end();
      bool value=fresh||node->item.value!=item.value,focus=(fresh||!node->item.focused)&&item.focused,enabled=node->item.enabled!=item.enabled;
      if(value||focus||enabled){node->AddRef();changes.push_back({node,value,focus,enabled,node->item.value,node->item.enabled});}
      node->item=item;node->present=true;children.push_back(node);
    }
    structure=previous!=children;
    for(auto it=byKey.begin();it!=byKey.end();) {
      if(!it->second->present){it->second->Release();it=byKey.erase(it);}else ++it;
    }
  }
  if(structure)UiaRaiseStructureChangedEvent(rootProvider,2,nullptr,0);
  for(auto& change:changes) {
    if(change.value) {
      VARIANT before{},after{};before.vt=after.vt=VT_BSTR;
      before.bstrVal=SysAllocString(wide(change.oldValue).c_str());after.bstrVal=SysAllocString(wide(change.node->item.value).c_str());
      UiaRaiseAutomationPropertyChangedEvent(change.node,change.node->item.kind=="field"?UIA_ValueValuePropertyId:UIA_NamePropertyId,before,after);
      VariantClear(&before);VariantClear(&after);
      if(change.node->item.key=="notice"||change.node->item.key=="panel-title")UiaRaiseAutomationEvent(change.node,UIA_LiveRegionChangedEventId);
    }
    if(change.focus)UiaRaiseAutomationEvent(change.node,UIA_AutomationFocusChangedEventId);
    if(change.enabled){VARIANT before{},after{};before.vt=after.vt=VT_BOOL;before.boolVal=change.oldEnabled?VARIANT_TRUE:VARIANT_FALSE;after.boolVal=change.node->item.enabled?VARIANT_TRUE:VARIANT_FALSE;UiaRaiseAutomationPropertyChangedEvent(change.node,UIA_IsEnabledPropertyId,before,after);}
    change.node->Release();
  }
}
