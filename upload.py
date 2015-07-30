from __future__ import with_statement
import os
import sys


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
            print(c)
            if c.lower() not in ["y", "yes", "z", "j", "ja", "zes", ""]:
                # Z on US keyboard == Y on DE keyboard
                break

def git_pull():
    os.system("git pull")


if __name__ == "__main__":
    if len(sys.argv)==1:
        git_update()
        git_push()
    if "update" in sys.argv:
        git_update()
    if "pull" in sys.argv:
        git_pull()
    if "push" in sys.argv:
        git_push()
        
