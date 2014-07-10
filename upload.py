from __future__ import with_statement
import os

with open("changelog.rst") as cl:
    changelog = cl.read()

def git_update():
    with open("changelog.rst") as cl:
        changelog = cl.read()
    lines = changelog.splitlines()
    main = lines[6] # News
    os.system("git add *")
    os.system("git commit -m \"%s\"" % main) # Bad, old py2 syntay

def git_push():
    while 1:
        if not os.system("git push origin master"):
            input("Everthing should be uploaded now...")
            break
        else:
            c = input("Oops! It failed! Try again? [Y/n] ")
            if c.lower not in ["y", "yes", "z", "j", "ja", "zes", ""]:
                # Z on US keyboard == Y on DE keyboard
                break


if __name__ == "__main__":
    git_update()
    git_push()
