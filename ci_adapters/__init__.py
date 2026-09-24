import os


def detect_platform() -> str:
    """Best-effort detection of the CI platform InfraScan is running under."""
    if os.getenv('BITBUCKET_BUILD_NUMBER'):
        return 'bitbucket'
    if os.getenv('GITHUB_ACTIONS'):
        return 'github'
    return 'none'
