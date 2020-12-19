mkdir -p src/main/java/com/niton/jauth/config/
touch src/main/java/com/niton/jauth/config/AuthConfig.java > /dev/null
java -jar tscfg.jar --spec config.cfg --pn com.niton.jauth.config --cn AuthConfig --dd src/main/java/com/niton/jauth/config --durations



