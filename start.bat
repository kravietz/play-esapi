cd %~dp0
set JAVA_OPTS=-Djava.compiler=NONE -Xdebug -javaagent:%~dp0\seekerHelper.jar -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=8000
set JAVACMD=javaw.exe
call bin\play-esapi.bat