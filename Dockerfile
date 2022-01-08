FROM scratch
ADD ./bin/main /main
COPY ./log /log
COPY ./data /data
ENV PORT 8080
EXPOSE 8080
ENTRYPOINT ["/main"]