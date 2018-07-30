# StupidSimpleHooking
Extremely simple hooking library for x86 or x64


This is a horrendously simple library for creating hooks in Windows.  
To compile with vc++: 
  
cl /c /EHsc hooks.cpp  
lib hooks.obj
  
  
  
### Usage:  
The simplest way to use this is to use the Detour wrapper class.  
All you have to do is set the target address and replacement address with either the  
`set` function or constructor. Ie.  
```
Detour detour(targetAddr, replacementAddr);

detour.set(targetAddr, replacementAddr);
```
After that all you have to do is call the class member functions `hook()` 
to hook the target and `unhook()` to unhook the target
  
  
While I have not tested it, this "library" (I say library in quotes bc its just so simple)
should work with standard c as well. To use in standard c first create a `BYTE` (`unsigned char`)
array of 6 elements for x86 or 12 elements for x64.  
Call `hook_hookFunction(targetAddr, replacementAddr, backup)` to hook the function at targetAddr  
the backup parameter is the byte array created previously.  
To unhook call `hook_unhookFunction(targetAddr, backup)` and pass the target function's address and  
backup array.
  
For further information refer to the header file
