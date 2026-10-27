#pragma once
// ABI declarations absent from GHC 9.10's minimal MinGW SDK. Interface IDs and
// method order follow Microsoft's public UIAutomationCore.idl contract:
// https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders/um
#ifndef __IRawElementProviderFragment_INTERFACE_DEFINED__
enum NavigateDirection {NavigateDirection_Parent=0,NavigateDirection_NextSibling=1,NavigateDirection_PreviousSibling=2,NavigateDirection_FirstChild=3,NavigateDirection_LastChild=4};
struct UiaRect {double left,top,width,height;};
struct IRawElementProviderFragmentRoot;
MIDL_INTERFACE("f7063da8-8359-439c-9297-bbc5299a7d87") IRawElementProviderFragment : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE Navigate(NavigateDirection,IRawElementProviderFragment**)=0;
  virtual HRESULT STDMETHODCALLTYPE GetRuntimeId(SAFEARRAY**)=0;
  virtual HRESULT STDMETHODCALLTYPE get_BoundingRectangle(UiaRect*)=0;
  virtual HRESULT STDMETHODCALLTYPE GetEmbeddedFragmentRoots(SAFEARRAY**)=0;
  virtual HRESULT STDMETHODCALLTYPE SetFocus()=0;
  virtual HRESULT STDMETHODCALLTYPE get_FragmentRoot(IRawElementProviderFragmentRoot**)=0;
};
MIDL_INTERFACE("620ce2a5-ab8f-40a9-86cb-de3c75599b58") IRawElementProviderFragmentRoot : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE ElementProviderFromPoint(double,double,IRawElementProviderFragment**)=0;
  virtual HRESULT STDMETHODCALLTYPE GetFocus(IRawElementProviderFragment**)=0;
};
MIDL_INTERFACE("54fcb24b-e18e-47a2-b4d3-eccbe77599a2") IInvokeProvider : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE Invoke()=0;
};
MIDL_INTERFACE("c7935180-6fb3-4201-b174-7df73adbf64a") IValueProvider : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE SetValue(LPCWSTR)=0;
  virtual HRESULT STDMETHODCALLTYPE get_Value(BSTR*)=0;
  virtual HRESULT STDMETHODCALLTYPE get_IsReadOnly(BOOL*)=0;
};
#ifdef __CRT_UUID_DECL
__CRT_UUID_DECL(IRawElementProviderFragment,0xf7063da8,0x8359,0x439c,0x92,0x97,0xbb,0xc5,0x29,0x9a,0x7d,0x87)
__CRT_UUID_DECL(IRawElementProviderFragmentRoot,0x620ce2a5,0xab8f,0x40a9,0x86,0xcb,0xde,0x3c,0x75,0x59,0x9b,0x58)
__CRT_UUID_DECL(IInvokeProvider,0x54fcb24b,0xe18e,0x47a2,0xb4,0xd3,0xec,0xcb,0xe7,0x75,0x99,0xa2)
__CRT_UUID_DECL(IValueProvider,0xc7935180,0x6fb3,0x4201,0xb1,0x74,0x7d,0xf7,0x3a,0xdb,0xf6,0x4a)
#endif
#endif
#ifndef UIA_ButtonControlTypeId
#define UIA_ButtonControlTypeId 50000
#define UIA_EditControlTypeId 50004
#define UIA_TextControlTypeId 50020
#define UIA_PaneControlTypeId 50033
#endif
#ifndef UIA_InvokePatternId
#define UIA_InvokePatternId 10000
#define UIA_ValuePatternId 10002
#endif
#ifndef UIA_LiveSettingPropertyId
#define UIA_LiveSettingPropertyId 30135
#endif
#ifndef UIA_LiveRegionChangedEventId
#define UIA_LiveRegionChangedEventId 20024
#define UIA_AutomationFocusChangedEventId 20005
#endif
