#pragma once
#ifdef _WIN32
// These stable SDL2 ABI calls are already linked by Monomer. Avoid SDL2main's
// application entry-point library when building a GHC executable on Windows.
struct SDL_Window;
using Uint32=unsigned int;
extern "C" SDL_Window* SDL_GetWindowFromID(Uint32);
extern "C" void SDL_GetWindowSize(SDL_Window*,int*,int*);
#else
#include <SDL.h>
#endif
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

struct BCItem {
  std::string key, label, kind, value;
  bool enabled, focused;
  double x, y, w, h;
};
static std::vector<BCItem> incoming;
static std::mutex actionMutex;
static std::vector<std::pair<std::string,std::string>> actions;
static void enqueue(const std::string& key, const std::string& value="") {
  std::lock_guard<std::mutex> lock(actionMutex);
  // Bound requests from assistive clients; the normal model guards every action.
  if (actions.size()<256) actions.emplace_back(key,value);
}
static std::string jsonString(const std::string& text) {
  std::string result="\"";
  const char* hex="0123456789abcdef";
  for (unsigned char c:text) {
    if(c=='"'||c=='\\') {result+='\\';result+=c;}
    else if(c<32) {result+="\\u00";result+=hex[c>>4];result+=hex[c&15];}
    else result+=c;
  }
  return result+'"';
}
static SDL_Window* appWindow() {
  for(Uint32 id=1;id<128;id++) if(auto* w=SDL_GetWindowFromID(id)) return w;
  return nullptr;
}
extern "C" void bc_ax_begin() {incoming.clear();}
extern "C" void bc_ax_item(const char* key,const char* label,const char* kind,const char* value,
    int enabled,int focused,double x,double y,double w,double h) {
  incoming.push_back({key,label,kind,value,enabled!=0,focused!=0,x,y,w,h});
}
extern "C" char* bc_ax_poll() {
  std::lock_guard<std::mutex> lock(actionMutex);
  std::string json="[";
  for(auto& a:actions) {
    if(json.size()>1)json+=',';
    json+="{\"key\":"+jsonString(a.first)+",\"value\":"+jsonString(a.second)+'}';
  }
  json+=']';actions.clear();
  auto* out=static_cast<char*>(std::malloc(json.size()+1));
  if(out)std::memcpy(out,json.c_str(),json.size()+1);
  return out;
}
