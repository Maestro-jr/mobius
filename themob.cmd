@echo off
rem themob launcher (Windows): run the console from a checkout without installing.
rem
rem `pip install .` gives you a `themob` command directly; this is for running
rem straight from a clone. It picks a working Python 3 and puts this directory on
rem PYTHONPATH so `python -m themob` resolves the package beside it.
rem
rem Put this folder on PATH, or call it as `themob.cmd`. Set THEMOB_PYTHON to
rem force a specific interpreter.
rem
rem Each interpreter branch is its own label with `exit /b %ERRORLEVEL%` on its
rem own line, so the launcher exits with Python's real code (0/1/2) for a
rem pipeline to branch on. Inside a parenthesised block cmd would expand
rem %ERRORLEVEL% too early and always report success.
setlocal
set "PYTHONPATH=%~dp0;%PYTHONPATH%"

if defined THEMOB_PYTHON goto :custom
where py >nul 2>nul && goto :usepy
where python >nul 2>nul && goto :usepython
echo themob: no Python 3 found on PATH. Set THEMOB_PYTHON to your interpreter. 1>&2
exit /b 127

:custom
"%THEMOB_PYTHON%" -m themob %*
exit /b %ERRORLEVEL%

:usepy
py -3 -m themob %*
exit /b %ERRORLEVEL%

:usepython
python -m themob %*
exit /b %ERRORLEVEL%
