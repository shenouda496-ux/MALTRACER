import base64
import os


def get_emails(service, max_results=20):
    results = (
        service.users()
        .messages()
        .list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=max_results
        )
        .execute()
    )

    return results.get("messages", [])


def get_email(service, message_id):
    return (
        service.users()
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="full"
        )
        .execute()
    )


def get_headers(message):
    headers = {}

    for header in message["payload"].get("headers", []):
        headers[header["name"]] = header["value"]

    return headers


def get_body(message):
    payload = message["payload"]

    def decode(data):
        return base64.urlsafe_b64decode(
            data.encode("UTF-8")
        ).decode(
            "utf-8",
            errors="ignore"
        )

    if "parts" in payload:
        for part in payload["parts"]:
            mime = part.get("mimeType")
            body = part.get("body", {})
            data = body.get("data")

            if not data:
                continue

            if mime == "text/html":
                return decode(data)

            if mime == "text/plain":
                return decode(data)

    data = payload.get("body", {}).get("data")

    if data:
        return decode(data)

    return ""


def download_attachments(
    service,
    message,
    download_dir="attachments"
):
    os.makedirs(download_dir, exist_ok=True)

    files = []

    payload = message.get("payload", {})

    if "parts" not in payload:
        return files

    for part in payload["parts"]:
        filename = part.get("filename")

        if not filename:
            continue

        body = part.get("body", {})
        attachment_id = body.get("attachmentId")

        if not attachment_id:
            continue

        attachment = (
            service.users()
            .messages()
            .attachments()
            .get(
                userId="me",
                messageId=message["id"],
                id=attachment_id
            )
            .execute()
        )

        data = attachment.get("data")

        if not data:
            continue

        file_data = base64.urlsafe_b64decode(
            data.encode("UTF-8")
        )

        path = os.path.join(
            download_dir,
            filename
        )

        with open(path, "wb") as f:
            f.write(file_data)

        files.append(path)

    return files