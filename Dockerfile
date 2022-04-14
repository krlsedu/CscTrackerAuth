
FROM adoptopenjdk/openjdk11:alpine-jre
WORKDIR /opt/app

ARG JAR_FILE=target/csctracker-auth.jar

COPY ${JAR_FILE} app.jar

ENTRYPOINT ["java","-Dfile.encoding=UTF-8","-jar","app.jar"]