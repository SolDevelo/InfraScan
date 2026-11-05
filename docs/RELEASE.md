# InfraScan Release Process

Steps to release a new version of InfraScan: the Docker Hub image, the git tags and the GitHub Marketplace action.

## Release checklist

- [ ] CI on `main` passes (`.github/workflows/infrascan-ci.yml`, which also runs the version check below).
- [ ] Version bumped in `cli.py` (`__version__`).
- [ ] Same version in `action.yml`'s default image (`soldevelo/infrascan:<version>` in the "Resolve InfraScan image" step). The action runs that image, so pinning the action pins the scanner; CI fails if it does not match `__version__`.
- [ ] Version number updated in `README.md` (if applicable).
- [ ] Version string updated in the web app footer: `templates/index.html`, `report.html`, `project_scans.html` and `supported_projects.html` each contain their own hardcoded `InfraScan vX.Y.Z` string (there is no shared partial, and this has been missed in past releases).
- [ ] Release notes added as `docs/RELEASE_NOTES_<version>.md`.
- [ ] Docker Hub image built and pushed (`latest` and `<version>`). Do this **before** pushing the git tag and moving `v1`: from then on the action pulls `<version>`, and every workflow using it fails until that tag exists.
- [ ] Git tag created and pushed.
- [ ] Major version tag (e.g. `v1`) updated.
- [ ] GitHub Release published to the Marketplace.

---

## 1. Docker Hub release

The `soldevelo/infrascan` image contains both the web app and the CLI.

### Log in
You need push access to the `soldevelo` organization.
```bash
docker login
```

### Build and push
Replace `<version>` with the new version (e.g. `1.1.0`).
```bash
# Build
docker build -t soldevelo/infrascan:latest -t soldevelo/infrascan:<version> .

# Push
docker push soldevelo/infrascan:latest
docker push soldevelo/infrascan:<version>
```

---

## 2. Git tags and GitHub release

InfraScan is published as a GitHub Action, and users reference it by tag, so the tags must always point at a valid release.

### Create the version tag
```bash
git tag -a v1.1.0 -m "Release v1.1.0"
git push origin v1.1.0
```

> [!CAUTION]
> Deleting the major version tag (`v1`) on the remote without immediately pushing a replacement breaks every workflow that uses `@v1`, and the Marketplace page then points at missing code or shows errors.
>
> Never delete the major tag on the remote. Move it with a force push instead:

```bash
# Point the local major tag at the release commit
git tag -fa v1 -m "Update v1 to v1.1.0"

# Force-push the major tag
git push origin v1 --force
```

---

## 3. Publishing to the GitHub Marketplace

1. Open the [InfraScan releases](https://github.com/soldevelo/infrascan/releases) page.
2. Click **Draft a new release**.
3. Select the tag you pushed (e.g. `v1.1.0`).
4. Set the release title (e.g. `InfraScan v1.1.0`).
5. Describe the changes (the "Generate release notes" button can help, or use the release notes file).
6. Make sure **Publish this Action to the GitHub Marketplace** is checked.
7. Check the `action.yml` metadata in the preview.
8. Click **Publish release**.

---

## 4. Local verification

Before releasing, check that the image works.

### Web mode
```bash
docker run -d -p 5000:5000 --name infrascan-test soldevelo/infrascan:latest web
# Open http://localhost:5000
docker stop infrascan-test && docker rm infrascan-test
```

### CLI mode
```bash
docker run --rm -v $(pwd):/scan soldevelo/infrascan:latest --scanner regex
```

---

## Troubleshooting the Marketplace page

If the Marketplace page shows errors after a release:
1. **`action.yml`**: check that the syntax is valid and the required fields (`name`, `description`, `runs`) are present.
2. **Tags**: check that the `v1` tag points at a commit that contains `action.yml`.
3. **Draft state**: the listing is not updated until the release is **published** (not just drafted).
4. **Delay**: the Marketplace can take a few minutes to show changes.
