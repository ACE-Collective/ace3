"""Encrypted-secrets management API (ACE API v2).

Write-only management of the named secrets that back ``encrypted:<name>`` config references (stored
in the ``encrypted_passwords`` table). Values can be set or deleted but are never read back to a
client; the API only ever reports a secret's name and status.
"""
