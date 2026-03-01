rule always_match
{
    meta:
        description = "matches Hello, world! with no meta_tags directive"
    strings:
        $s = "Hello, world!"
    condition:
        $s
}

rule meta_tagged_email_body
{
    meta:
        description = "matches Hello, world! only when content_type=email_body tag is provided"
        meta_tags = "content_type=email_body"
    strings:
        $s = "Hello, world!"
    condition:
        $s
}

rule meta_tagged_source_imap
{
    meta:
        description = "matches Hello, world! only when source=imap tag is provided"
        meta_tags = "source=imap"
    strings:
        $s = "Hello, world!"
    condition:
        $s
}

rule meta_tagged_no_match_content
{
    meta:
        description = "has email_body tag but string does not match the target"
        meta_tags = "content_type=email_body"
    strings:
        $s = "this string does not exist in the target file"
    condition:
        $s
}
