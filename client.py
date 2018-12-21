import json
import socket
import argparse
from stomp import *
access_token = {}
current_token = ""
REQUIRE_USER_REPLACE_CMDS = [
    "delete", "logout", "invite", "list-invite", "accept-invite",
    "list-friend", "post", "receive-post", "send", "create-group",
    "list-group", "list-joined", "join-group", "send-group"
]

#IP = "140.113.207.51"
#PORT = 8010
IP = None
PORT = None
mqConn = None


class myListener(ConnectionListener):

    def on_message(self, headers, body):
        """
        :param dict headers:
        :param body:
        """
        body_dict = json.loads(body)
        if (body_dict["type"] == "queue"):
            print('<<<{}->{}: {}>>>'.format(body_dict['from'], body_dict['to'],
                                            body_dict['content']))
        elif body_dict["type"] == "topic":
            print('<<<{}->Group<{}>: {}>>>'.format(
                body_dict['from'], body_dict['to'], body_dict['content']))


def mqSend(msg):
    pass


def send_as_bytes(msg, s):
    b_msg = bytes(msg, encoding="utf-8")
    s.sendall(b_msg)


def command(cmds):
    # special command "exit"
    if (cmds[0] == "exit"):
        access_token.clear()
        exit(0)

    BUFFSIZE = 1024
    command_type = cmds[0]
    user_name = ""
    # replace user to its token if exists
    if (command_type in REQUIRE_USER_REPLACE_CMDS):
        for index, cmd in enumerate(cmds):
            if (cmd in access_token):
                user_name = cmd
                cmds[index] = access_token[user_name]
                break

    # send to server and receive response
    with socket.socket() as s:
        s.connect((IP, PORT))
        msg = ' '.join(cmds)
        #print(msg)
        send_as_bytes(msg, s)

        response = json.loads(s.recv(BUFFSIZE), encoding="utf-8")
    # if success
    if (response["status"] == 0):
        # login
        if (command_type == "login"):
            user_name = cmds[1]
            #store token
            access_token[user_name] = response["token"]
            current_token = response["token"]
            global mqConn
            mqConn = Connection([(
                response["mqServer"],
                response["mqPort"],
            )])
            mqConn.set_listener('', myListener())
            mqConn.start()
            mqConn.connect(response["mqUser"], response["mqPassword"])
            for queue in response["queues"]:
                mqConn.subscribe('/queue/{}'.format(queue), response["token"])
            for group in response["groups"]:
                mqConn.subscribe('/topic/{}'.format(group), response["token"])

            #mqConn.send('/queue/test', 'a test message')
            #mqConn.disconnect()
        # delete
        elif (command_type == "delete"):
            access_token.pop(user_name)
            current_token = ""
        # logout
        elif (command_type == "logout"):
            access_token.pop(user_name)
            current_token = ""
        # list-invite
        elif (command_type == "list-invite"):
            if (len(response["invite"]) > 0):
                for invitation in response["invite"]:
                    print(invitation)
            else:
                print("No invitations")
        # list-friend
        elif (command_type == "list-friend"):
            if (len(response["friend"]) > 0):
                for friend in response["friend"]:
                    print(friend)
            else:
                print("No friends")
        # receive-post
        elif (command_type == "receive-post"):
            if (len(response["post"]) > 0):
                for post in response["post"]:
                    print("{}: {}".format(post["id"], post["message"]))
            else:
                print("No posts")

        elif (command_type == "list-group"):
            if len(response["groups"]) == 0:
                print("No groups")
            else:
                for group in response["groups"]:
                    print(group)

        elif command_type == "list-joined":
            if len(response["groups"]) == 0:
                print("No groups")
            else:
                for group in response["groups"]:
                    print(group)
        elif command_type == "join-group":
            mqConn.subscribe('/topic/{}'.format(response["subscription"]),
                             access_token[response["user"]])

    return response
    """
    # open socket
    with socket.socket() as s:
        # connect to server
        s.connect((IP, PORT))

        if (cmds[0] == "register"):
            # register <id> <password>
            #msg = "{} {} {}".format(cmds[0], cmds[1], cmds[2])
            msg = ' '.join(cmds)
            send_as_bytes(msg, s)
            response = json.loads(s.recv(BUFFSIZE), encoding="utf-8")

        elif (cmds[0] == "login"):
            # login <id> <password>
            #msg = "{} {} {}".format(cmds[0], cmds[1], cmds[2])
            msg = ' '.join(cmds)
            send_as_bytes(msg, s)
            response = json.loads(s.recv(BUFFSIZE), encoding="utf-8")

            # if success
            if (response["status"] == 0):
                #store token
                access_token[cmds[1]] = response["token"]
                current_token = response["token"]

        else:  # none assigned case
            return -1

        return response
    """


def main():
    # argument input [(IP, PORT)]
    # usage:
    # python3 ./client.py IP PORT
    parser = argparse.ArgumentParser()
    parser.add_argument("IP")
    parser.add_argument("PORT")
    args = parser.parse_args()
    global IP
    IP = args.IP
    global PORT
    PORT = int(args.PORT)
    #print(IP)
    #print(PORT)
    #i = 0
    while (True):
        usr_cmds = input("").split()  # split commands into list
        if (len(usr_cmds) <= 0):
            continue
        # response is a dict that parsed the response json
        response = command(usr_cmds)
        #response = json.loads(str(command(usr_cmds), encoding="utf-8"))

        # output to user
        if ("message" in response):
            print(response["message"])
        # if output is a list, it can be found in response["list"]
        # if ("list" in response):
        #     if len(response["list"]) == 0:
        #         print ()
        #     for item in response["list"]:
        #         print(item)


main()