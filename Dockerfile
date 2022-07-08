
FROM ghcr.io/graalvm/graalvm-ce:ol8-java11-20.3.6
WORKDIR /opt/app

ARG JAR_FILE=target/csctracker-auth.jar

COPY ${JAR_FILE} app.jar

ENTRYPOINT ["java","-Dfile.encoding=UTF-8 -XX:+UseSerialGC","-jar","app.jar"]