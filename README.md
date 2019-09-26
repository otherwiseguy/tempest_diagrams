# Parse tempest logs and produce a sequence diagram

Usage: python parse.py <filename> > out.html

This is currently extremely brittle. The file can't have partial records
for example.

## TODO:
[ ] Make log line matching more robust
[ ] Handle an error or 12
[ ] Actually come up with a way to collapsibly display header/body info
[ ] Add filtering for things like error responses, req-ids, services, etc.
[ ] Optionally show log lines that are between request/response diagrams
[ ] Make the code even minimally readable
[ ] Add separate renderers
[ ] Parse the Accept header and properly decode the response body
