# Secret Scanner

A simple tool to scan directories for secrets using regular expressions.

## Install

Install using either [`pip`](https://pypi.org/project/pip/), [`pipx`](https://pypi.org/project/pipx/) or your Python installer of choice

```
pipx install secretscanner
```

## Usage

To scan a directory and print the files with secrets

```
secretscanner DIRECTORY
```

To also display info on the tokens that have been found pass the `-v`/`--verbose` flag.

To hide the output pass the `-q`/`--quiet` flag.

To output the tokens found as josn pass the `-j`/`--json` flag.

If secrets are found the tool exits with exit code `1`

## Output

### Default output

```
Files with embedded secrets:
  /secretscanner/tests/dir/github/github.txt
  /secretscanner/tests/dir/pypi/pypi.txt
  /secretscanner/tests/dir/digitalocean/digitalocean.txt
```

### Verbose Output

```
Files with embedded secrets:
  /secretscanner/tests/dir/github/github.txt
    - Issuer: github
      Type: pat
      Token: ghp_GHJSGSJHGgjhgshjagjgasjgjhJHGHJJGJGHJGHJG76y78bhjksdbahjkghj
    - Issuer: github
      Type: oauth
      Token: gho_GHJSGSJHGgjhgshjagjgasjgjhJHGHJJGJGHJGHJG76y78bhjksdbahjkghj
    - Issuer: github
      Type: user-to-server
      Token: ghu_GHJSGSJHGgjhgshjagjgasjgjhJHGHJJGJGHJGHJG76y78bhjksdbahjkghj
    - Issuer: github
      Type: server-to-server
      Token: ghs_GHJSGSJHGgjhgshjagjgasjgjhJHGHJJGJGHJGHJG76y78bhjksdbahjkghj
    - Issuer: github
      Type: refresh
      Token: ghr_GHJSGSJHGgjhgshjagjgasjgjhJHGHJJGJGHJGHJG76y78bhjksdbahjkghj
  /secretscanner/tests/dir/pypi/pypi.txt
    - Issuer: pypi
      Type: pat
      Token:
        pypi-AgEIcHlwaS5vcmcCJGzcex4tRk1EkM_jg2KTYkrCissgG2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX
        0AAAYgjeEtcvL8TyDUVri6iM0LTc2YzUtNDgwYy05NTA3LTlkMjBmZjY2MWY0
  /secretscanner/tests/dir/digitalocean/digitalocean.txt
    - Issuer: digitalocean
      Type: pat
      Token:
        dop_v1_GHJSGSJHGgjhgshjagjgasjgjhJHGHJJGJGHJGHJG76y78bhjksdbahjkghjJHGHJJGJGHJGHJG76y78
        bhjksdbahjkghj
    - Issuer: digitalocean
      Type: oauth
      Token:
        doo_v1_GHJSGSJHGgjhgshjagjgasjgjhJHGHJJGJGHJGHJG76y78bhjksdbahjkghjJHGHJJGJGHJGHJG76y78
        bhjksdbahjkghj
    - Issuer: digitalocean
      Type: refresh
      Token:
        dor_v1_GHJSGSJHGgjhgshjagjgasjgjhJHGHJJGJGHJGHJG76y78bhjksdbahjkghjJHGHJJGJGHJGHJG76y78
        bhjksdbahjkghj
```

## Recognized Secrets

The tool currently recognizes the following secret types

- Github access tokens
- PyPI access tokens
- Digital Ocean access tokens
