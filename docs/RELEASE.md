# InfraScan Release Process

This document outlines the steps required to release a new version of InfraScan, including Docker Hub images and the GitHub Marketplace Action.

## 📌 Release Checklist

- [ ] All tests pass on `main` branch.
- [ ] Version number updated in `README.md` (if applicable).
- [ ] Docker Hub image built and pushed (`latest` and `<version>`).
- [ ] Git tag created and pushed.
- [ ] Major version tag (e.g., `v1`) updated.
- [ ] GitHub Release published to Marketplace.

---

## 📦 1. Docker Hub Release

The unified image `soldevelo/infrascan` contains both the Web App and the CLI.

### Login
Ensure you have permissions for the `soldevelo` organization.
```bash
docker login
```

### Build and Push
Replace `<version>` with the new version (e.g., `v1.0.6`).
```bash
# Build
docker build -t soldevelo/infrascan:latest -t soldevelo/infrascan:<version> .

# Push
docker push soldevelo/infrascan:latest
docker push soldevelo/infrascan:<version>
```

---

## 🏷️ 2. Git Tagging & GitHub Release

InfraScan is published as a GitHub Action. Proper tagging is critical for users and the Marketplace.

### Creating the Version Tag
```bash
# Create a new version tag
git tag -a v1.0.6 -m "Release v1.0.6"
git push origin v1.0.6
```

> [!CAUTION]
> **The Tag Issue that Broke the Marketplace:**
> Failing to properly update the major version tag or deleting it without a replacement can break existing workflows and cause the GitHub Marketplace page to point to non-existent code or show errors.
> 
> **NEVER** just delete the major tag on the remote without immediately pushing the new one. Use the following "force" method to ensure continuity.

```bash
# Update the local major tag to the latest commit
git tag -fa v1 -m "Update v1 to v1.0.6"

# Force push the major tag to the remote
git push origin v1 --force
```

---

## 🛒 3. Publishing to GitHub Marketplace

1. Go to the [InfraScan Releases](https://github.com/soldevelo/infrascan/releases) page.
2. Click **Draft a new release**.
3. Select the tag you just pushed (e.g., `v1.0.6`).
4. Set the Release Title (e.g., `InfraScan v1.0.6`).
5. Describe the changes (you can use the "Generate release notes" button).
6. **Marketplace Publication**: Ensure the checkbox **"Publish this Action to the GitHub Marketplace"** is checked.
7. Verify the `action.yml` metadata is correct in the preview.
8. Click **Publish release**.

---

## 🛠️ 4. Local Verification

Before releasing, always verify the image works as expected.

### Test Web Mode
```bash
docker run -d -p 5000:5000 --name infrascan-test soldevelo/infrascan:latest
# Visit http://localhost:5000
docker stop infrascan-test && docker rm infrascan-test
```

### Test CLI Mode
```bash
docker run --rm -v $(pwd):/scan soldevelo/infrascan:latest --scanner regex
```

---

## 🚑 Troubleshooting the Marketplace Page

If the Marketplace page shows errors after a release:
1. **Check `action.yml`**: Ensure the syntax is valid and all required fields (`name`, `description`, `runs`) are present.
2. **Tag Consistency**: Ensure the `v1` tag points to a commit that contains the `action.yml`.
3. **Draft State**: The Marketplace listing won't update until the release is **Published** (not just a draft).
4. **Cache Delay**: GitHub Marketplace can take a few minutes to reflect changes.
