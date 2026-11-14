- File DLP (uploads): only files are checked now. Chat messages, form posts and
  other web API calls to an inspected site are no longer treated as files, so a
  policy no longer blocks typing "Hi" into ChatGPT. Files sent as multipart,
  to object storage (Azure Blob, S3, Google resumable uploads, tus) or with a
  file name are still checked, and the event shows the file name (#494).
- DLP phone number detector: a bare 10-digit number starting with 1 (a Unix
  timestamp) is no longer reported as a phone number (#494).
