#!/usr/bin/python3
# usage: azure_tester.py aztestfile.json [BUILTIN|CUSTOM]
import subprocess
import sys
import json
import re
import time

# various globals
with open(".az_account_info") as f:
    S = json.load(f)
# S = { "PRIV_USER": "myemail@outlook.com", "PRIV_CONFIG_DIR": "~/AZURE_CONFIG_PRIV", "NONPRIV_USER": "nonpriv@myemailoutlook.onmicrosoft.com", "NONPRIV_CONFIG_DIR": "~/AZURE_CONFIG_NONPRIV" }

# load variables to be interpolated into az commands
with open("azvars.json") as f:
    V = json.load(f)

# load the script that has the commands for the test case we are working on
TESTCASE=sys.argv[1]
USE_BUILTIN = (len(sys.argv) > 2 and sys.argv[2].upper() == "BUILTIN")
print(f"Doing testcase {TESTCASE}. Builtin roles:",USE_BUILTIN)
input("Hit any key to continue...")
with open(TESTCASE) as f:
    T = json.load(f)

def generate_az_cmd (p_user, p_cmd):
    v_cmd = "export AZURE_CONFIG_DIR={} ;{} ".format(S[p_user + "_CONFIG_DIR"],  p_cmd)
    return v_cmd

def run_az_cmd (p_user, p_cmd):
    if (p_user != "PRIV" and p_user != "NONPRIV"):
        raise ValueError("run_cmd: p_user must be PRIV or NONPRIV")
    v_cmd = generate_az_cmd(p_user, p_cmd)
    print(" ", p_cmd)
    result=subprocess.run(v_cmd, shell = True, capture_output=True)
    # add in automatic sleep for some seconds if doing a create or update - see if this helps with timing issues
    m = re.search("(update|create|delete)", p_cmd)
    if m:
        time.sleep(5)
    return result

def do_login(p_user):
    # check if logged in
    print("Checking if {} user is logged in".format(p_user))
    uname=S[p_user + "_USER"]
    r = run_az_cmd(p_user, "az account show")
    if (r.returncode == 0):
        j = bstr2json(r.stdout)
        if (j['user']['name'] != uname):
            raise ValueError("AZ login is not {} as expected.  It is {}".format(uname, j[0]['user']['name']))
        S["SUBSCRIPTION_ID"] = j["id"]
        return
    print("*** Logging in {} user {}".format(p_user, S[p_user + "_USER"]))
    r = run_az_cmd(p_user, "az login")
    if (r.returncode != 0):
        raise ValueError("Error logging into azure for ", S[p_user + "_USER"])
    else:
        j = bstr2json(r.stdout)[0]
        S["SUBSCRIPTION_ID"] = j["id"]
        if (j['user']['name'] != uname):
            raise ValueError("AZ login is not {} as expected.  It is {}".format(uname, j[0]['user']['name']))

def bstr2json(p_str):
    return json.loads(p_str.decode('utf8'))

def run_cmd_list(p_user, p_list_type, p_cmds, p_show_output):
    for c in p_cmds:
        while (1 == 1):
            print("--", do_substitutions(c[0]))
            result = run_az_cmd(p_user, do_substitutions(c[1]))
            if (p_show_output):
                print(" ReturnCode: {}\n Stdout: {}\n  Stderr: {}".format(result.returncode, result.stdout, result.stderr))
            if (result.returncode == 0):
                break
            print("  **Error: ", result.stderr)
            if (p_list_type == "test"):
                m = re.match(".*does not have authorization to perform action '([^']+)' over scope '([^']+).*", result.stderr.decode('utf8'), re.DOTALL)
                if m:
                    print("Need to grant action {}".format(m.group(1)))
                    if (not USE_BUILTIN):
                        add_custom_role_action(T["grants"]["customRole"], m.group(1)) # create the role

            tryAgain = input("Try again [y|n]: ")
            if (tryAgain != "y"):
                break
    return True

def do_substitutions(p_str):
    for k in V.keys():
        p_str = p_str.replace("$" + k + " ", V[k] + " ")
    return p_str

def grant_roles(p_roles):
    for role in p_roles:
       r = run_az_cmd("PRIV", 'az role assignment create --role "{}" --assignee {} --resource-group {}'.format(role, S["NONPRIV_USER"], V["v_dba_rg"]))
       if ( r.returncode != 0):
           raise Exception("Error granting role {}.  {}".format(role, r.stderr))

def strip_roles():
    r = run_az_cmd("PRIV", "az role assignment list --all --assignee {}".format(S["NONPRIV_USER"]))
    j = bstr2json(r.stdout)
    #print("Permissions are:", j)
    for p in bstr2json(r.stdout):
        print("Removing role {} on group {}".format(p['roleDefinitionName'], p['resourceGroup']))
        run_az_cmd("PRIV", "az role assignment delete --id '{}' ".format(p["id"]))

def add_custom_role_action(p_jrole, p_action):
    r = run_az_cmd("PRIV", f"az role definition list --name {p_jrole['name']}")
    j = bstr2json(r.stdout)
    if (len(j) > 0):
        j = j[0]
        #print("role exists: ", j)
    else:
        print("Creating role")
        r = run_az_cmd("PRIV", 
            'az role definition create --role-definition \'{{"Name":"{}","IsCustom": true,"Description": "{}","AssignableScopes": ["/subscriptions/{}"]}}\''.format(p_jrole["name"]
            , p_jrole["description"], S["SUBSCRIPTION_ID"]))
        if (r.returncode != 0):
            raise Exception(r.stderr)
        j = bstr2json(r.stdout)
    if (p_action > "" and not p_action in j["permissions"][0]["actions"]):
        j["permissions"][0]["actions"].append(p_action)
        r = run_az_cmd("PRIV", 'az role definition update --role-definition "{}" '.format(j))
        #print("output is ", r.returncode, r.stdout)

# login as the priv user & do the setup
print(f"Doing test case{TESTCASE}")

# do setup
print("\n\n------------------\n----Doing setup")
do_login("PRIV")
print(f"Subscription ID:{S['SUBSCRIPTION_ID']}")
strip_roles() # strip roles from NONPRIV user
run_cmd_list("PRIV", "setup", T["setup"],  False)
print("--Creating granting roles")
if (USE_BUILTIN):
    grant_roles(T["grants"]["builtinRoles"])
else:
    add_custom_role_action(T["grants"]["customRole"], "") # create the role
    grant_roles([T["grants"]["customRole"]["name"]])



# login as nonpriv user & do the test
print("\n\n------------------\n----Doing tests")
do_login("NONPRIV")
run_cmd_list("NONPRIV", "test", T["test"],  False)

print("\n\n------------------\n----Doing cleanup")
input("Hit enter to do cleanup")
run_cmd_list("PRIV", "cleanup", T["cleanup"],  False)






