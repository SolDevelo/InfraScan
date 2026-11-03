"""The one-line pointer to InfraScan Cloud (turned off with --no-tips).

Shown where only the person running the scan looks: the console summary, the
HTML report and the GitHub Actions step summary. Never in PR comments or the
Bitbucket Code Insights report, which everyone on the pull request sees.
"""

CLOUD_URL = "https://infrascan.soldevelo.com/"
TIP_TEXT = "Scan your live AWS account too"
TIP_LINK_TEXT = "InfraScan Cloud (free beta)"


def cloud_url(source: str) -> str:
    """Landing page URL tagged with where the tip was shown."""
    return f"{CLOUD_URL}?utm_source={source}&utm_campaign=beta"
