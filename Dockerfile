FROM nginx:stable-alpine

ADD ./conf/default.conf /etc/nginx/conf.d/default.conf
ADD ./src /usr/share/nginx/html

RUN echo "start nginx"
