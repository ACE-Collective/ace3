from saq.lazy_exports import lazy_getattr

# saq.modules.email imports nothing itself: importing any one email module ran this init, which imported all
# of them, encryption analyzers and saq.cracking included, so none of those could import EmailAnalysis at
# module level without a circular import. These names stay importable from saq.modules.email, each loaded
# the first time it is asked for (PEP 562).
_EXPORTS = {
    "KEY_PARSING_ERROR": "saq.modules.email.constants",
    "MailboxEmailAnalysis": "saq.modules.email.mailbox",
    "MailboxEmailAnalyzer": "saq.modules.email.mailbox",
    "EmailArchiveAction": "saq.modules.email.archive",
    "EmailArchiveResults": "saq.modules.email.archive",
    "EmailAnalysis": "saq.modules.email.rfc822",
    "EmailAnalyzer": "saq.modules.email.rfc822",
    "EmailConversationFrequencyAnalysis": "saq.modules.email.fa",
    "EmailConversationFrequencyAnalyzer": "saq.modules.email.fa",
    "EmailConversationAttachmentAnalysis": "saq.modules.email.fa",
    "EmailConversationAttachmentAnalyzer": "saq.modules.email.fa",
    "EmailConversationLinkAnalysis": "saq.modules.email.fa",
    "EmailConversationLinkAnalyzer": "saq.modules.email.fa",
    "MessageIDAnalysisV2": "saq.modules.email.message_id",
    "MessageIDAnalyzerV2": "saq.modules.email.message_id",
    "EmailLoggingAnalysis": "saq.modules.email.logging",
    "EmailLoggingAnalyzer": "saq.modules.email.logging",
    "MSOfficeEncryptionAnalysis": "saq.modules.email.encryption.msoffice",
    "MSOfficeEncryptionAnalyzer": "saq.modules.email.encryption.msoffice",
    "PDFEncryptionAnalysis": "saq.modules.email.encryption.pdf",
    "PDFEncryptionAnalyzer": "saq.modules.email.encryption.pdf",
    "ZipEncryptionAnalysis": "saq.modules.email.encryption.zip",
    "ZipEncryptionAnalyzer": "saq.modules.email.encryption.zip",
    "RarEncryptionAnalysis": "saq.modules.email.encryption.rar",
    "RarEncryptionAnalyzer": "saq.modules.email.encryption.rar",
}

__getattr__ = lazy_getattr(__name__, _EXPORTS)
