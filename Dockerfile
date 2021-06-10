FROM scratch
ADD ./bin/main /main
COPY ./log /log
ENV PORT 8080
EXPOSE 8080
ENTRYPOINT ["/main"]