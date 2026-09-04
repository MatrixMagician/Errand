FROM docker.io/library/alpine:3.22
RUN apk add --no-cache openssh-server && mkdir -p /run/sshd
EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e","-f","/etc/errand/sshd_config"]
