# The Workflow

1. Start the daemon: `colima start --cpus 2 --memory 4`

2. Build the environment: `./docker-run.sh build`

3. Launch the container: `./docker-run.sh run`

# Fix errors

```
➜ colima stop
unset TMPDIR
unset NIX_BUILD_TOP
unset TMP
unset TEMP
colima start
```
