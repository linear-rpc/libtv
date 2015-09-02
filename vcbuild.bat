@echo off

cd %~dp0

if /i "%1"=="help" goto help
if /i "%1"=="--help" goto help
if /i "%1"=="-help" goto help
if /i "%1"=="/help" goto help
if /i "%1"=="?" goto help
if /i "%1"=="-?" goto help
if /i "%1"=="--?" goto help
if /i "%1"=="/?" goto help

@rem Process arguments.
set config=
set target=Rebuild
set noprojgen=
set target_arch=x64
set vs_toolset=x64
set platform=x64
set shared=
set runtime_library=md
set vs_version="vs2013"
set with_doc=
set with_test=
set solution=tv.sln

:next-arg
if "%1"=="" goto args-done
if /i "%1"=="doc"          set with_doc=1&goto arg-ok
if /i "%1"=="test"         set with_test="-Dwith_test"&set solution=test.sln&goto arg-ok
if /i "%1"=="clean"        set target=Clean&goto arg-ok
if /i "%1"=="noprojgen"    set noprojgen=1&goto arg-ok
if /i "%1"=="x86"          set target_arch=ia32&set platform=WIN32&set vs_toolset=x86&goto arg-ok
if /i "%1"=="ia32"         set target_arch=ia32&set platform=WIN32&set vs_toolset=x86&goto arg-ok
if /i "%1"=="x64"          set target_arch=x64&set platform=x64&set vs_toolset=x64&goto arg-ok
if /i "%1"=="shared"       set shared="-Denable_shared"&goto arg-ok
if /i "%1"=="static"       set shared=&goto arg-ok
if /i "%1"=="mt"           set runtime_library=mt&&goto arg-ok
if /i "%1"=="md"           set runtime_library=md&&goto arg-ok
if /i "%1"=="vs2010"       set vs_version="vs2010"&goto arg-ok
if /i "%1"=="vs2012"       set vs_version="vs2012"&goto arg-ok
if /i "%1"=="vs2013"       set vs_version="vs2013"&goto arg-ok
:arg-ok
shift
goto next-arg
:args-done

if defined WindowsSDKDir goto project-gen
if defined VCINSTALLDIR goto project-gen

if /i %vs_version%=="vs2013" goto vc-set-2013
if /i %vs_version%=="vs2012" goto vc-set-2012
if /i %vs_version%=="vs2010" goto vc-set-2010
if /i %vs_version%=="vs2008" goto vc-set-2008

@rem Look for Visual Studio 2015
if not defined VS140COMNTOOLS goto vc-set-2013
if not exist "%VS140COMNTOOLS%\..\..\vc\vcvarsall.bat" goto vc-set-2013
call "%VS140COMNTOOLS%\..\..\vc\vcvarsall.bat" %vs_toolset%
set GYP_MSVS_VERSION=2015
goto select-target

:vc-set-2013
@rem Look for Visual Studio 2013
if not defined VS120COMNTOOLS goto vc-set-2012
if not exist "%VS120COMNTOOLS%\..\..\vc\vcvarsall.bat" goto vc-set-2012
call "%VS120COMNTOOLS%\..\..\vc\vcvarsall.bat" %vs_toolset%
set GYP_MSVS_VERSION=2013
goto project-gen

:vc-set-2012
@rem Look for Visual Studio 2012
if not defined VS110COMNTOOLS goto vc-set-2010
if not exist "%VS110COMNTOOLS%\..\..\vc\vcvarsall.bat" goto vc-set-2010
call "%VS110COMNTOOLS%\..\..\vc\vcvarsall.bat" %vs_toolset%
set GYP_MSVS_VERSION=2012
goto project-gen

:vc-set-2010
@rem Look for Visual Studio 2010
if not defined VS100COMNTOOLS goto vc-set-2008
if not exist "%VS100COMNTOOLS%\..\..\vc\vcvarsall.bat" goto vc-set-2008
call "%VS100COMNTOOLS%\..\..\vc\vcvarsall.bat" %vs_toolset%
set GYP_MSVS_VERSION=2010
goto project-gen

:vc-set-2008
@rem Look for Visual Studio 2008
if not defined VS90COMNTOOLS goto vc-set-notfound
if not exist "%VS90COMNTOOLS%\..\..\vc\vcvarsall.bat" goto vc-set-notfound
call "%VS90COMNTOOLS%\..\..\vc\vcvarsall.bat" %vs_toolset%
set GYP_MSVS_VERSION=2008
goto project-gen

:vc-set-notfound
echo Warning: Visual Studio not found
goto exit

:project-gen
@rem Skip project generation if requested.
if defined noprojgen goto msbuild

:have_gyp
if not defined PYTHON set PYTHON=python
"%PYTHON%" configure.py -Dtarget_arch=%target_arch% -Druntime_library=%runtime_library% %shared% %with_test%
if errorlevel 1 goto create-msvs-files-failed
if not exist %solution% goto create-msvs-files-failed
echo Project files generated.

:msbuild
@rem Check if VS build env is available
if defined VCINSTALLDIR goto msbuild-found
if defined WindowsSDKDir goto msbuild-found
echo Build skipped. To build, this file needs to run from VS cmd prompt.
goto exit

@rem Build the sln with msbuild.
:msbuild-found
msbuild /m %solution% /t:%target% /p:Configuration=Debug /p:Platform="%platform%" /clp:NoSummary;NoItemAndPropertyList;Verbosity=minimal /nologo
if errorlevel 1 exit /b 1
msbuild /m %solution% /t:%target% /p:Configuration=Release /p:Platform="%platform%" /clp:NoSummary;NoItemAndPropertyList;Verbosity=minimal /nologo
if errorlevel 1 exit /b 1

:documentation
if not defined with_doc goto exit
cd doc
doxygen Doxyfile > nul
if errorlevel 1 (
   echo Documentation skipped. To documentation, install doxygen.
   cd %~dp0
   goto exit
)
cd %~dp0

:create-msvs-files-failed
echo Failed to create vc project files.
exit /b 1

:help
echo vcbuild.bat [doc] [test] [clean] [noprojgen] [x86/x64] [mt/md] [static/shared] [vs2010/vs2012/vs2013]
echo Examples:
echo   vcbuild.bat        : builds library with /MD(d)
echo   vcbuild.bat mt     : builds library with /MT(d)
echo   vcbuild.bat shared : builds dll with /MD(d)
echo   vcbuild.bat vs2010 : tries to build library with Visual Studio 2010
echo   vcbuild.bat test   : builds library and test
goto exit

:exit
