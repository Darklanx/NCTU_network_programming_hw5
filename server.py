import json
import socket
import argparse
import threading
import time
from peewee import *
import uuid
import logging
from stomp import *
IP = "127.0.0.1"
PORT = 28888

db = SqliteDatabase('userData.db')
mqServerIP = "127.0.0.1"
mqServerPORT = 61613

# connect to mq
mqConn = Connection([(
    mqServerIP,
    mqServerPORT,
)])
mqConn.set_listener('', PrintingListener())
mqConn.start()
mqConn.connect('server', 'server', wait=True)


class User(Model):
    user_id = CharField(unique=True)
    password = CharField()
    token = CharField(unique=True)
    online = BooleanField(default=False)

    class Meta():
        database = db


class Invitation(Model):
    inviter = ForeignKeyField(User, backref="inviter")
    invitee = ForeignKeyField(User, backref="invitee")

    class Meta():
        database = db


class Friend(Model):
    userA = ForeignKeyField(User, backref="userA")
    userB = ForeignKeyField(User, backref="userB")

    class Meta():
        database = db


class Post(Model):
    user = ForeignKeyField(User, backref="user")
    content = CharField()

    class Meta():
        database = db


class Group(Model):
    name = CharField(unique=True)

    class Meta():
        database = db


class User_Group(Model):
    _user = ForeignKeyField(User, backref="user_group")
    group = ForeignKeyField(Group, backref="user_group")

    class Meta():
        database = db


def send_byte_json(msg, conn):
    response = json.dumps(msg)
    conn.sendall(bytes(response, encoding="utf-8"))


def check_token(inputs, conn):
    if len(inputs) == 1:
        return None, -1
    else:
        try:
            user = User.get(User.token == inputs[1])
        except User.DoesNotExist:
            return None, -1
    return user, 0


def handle(data, conn):
    inputs = data.decode('ascii').split()
    print(inputs)
    command_type = inputs[0]

    if command_type == "register":
        # format error
        if len(inputs) != 3:
            response = {
                "status": 1,
                "message": "Usage: register <id> <password>"
            }
            send_byte_json(response, conn)
            return

        # register
        id = inputs[1]
        password = inputs[2]
        db.connect(reuse_if_open=True)
        try:
            user = User.create(
                user_id=id, password=password, token=uuid.uuid4())
            user.save()
        except IntegrityError:  # id in use
            response = {
                "status": 1,
                "message": "{} is already used".format(id)
            }
            send_byte_json(response, conn)
            return

        response = {"status": 0, "message": "Success!"}
        send_byte_json(response, conn)

    elif command_type == "login":
        # format error
        if len(inputs) != 3:
            response = {"status": 1, "message": "Usage: login <id> <password>"}
            send_byte_json(response, conn)
            return
        id = inputs[1]
        password = inputs[2]
        try:
            login_usr = User.get(User.user_id == id)
        except User.DoesNotExist:  # no user
            response = {
                "status": 1,
                "message": "No such user or password error"
            }
            send_byte_json(response, conn)
            return

        if (login_usr.password != password):  # password error
            response = {
                "status": 1,
                "message": "No such user or password error"
            }
            send_byte_json(response, conn)
            return

        groups = [
            group.name for group in Group.select().join(User_Group).where(
                User_Group._user == login_usr)
        ]

        response = {
            "status": 0,
            "token": login_usr.token,
            "message": "Success!",
            "mqServer": "{}".format(mqServerIP),
            "mqPort": mqServerPORT,
            "mqUser": "user",
            "mqPassword": "user",
            "queues": [login_usr.token],
            "groups": groups
        }
        login_usr.online = True
        login_usr.save()
        send_byte_json(response, conn)

    elif command_type == "delete":
        user, rv = check_token(inputs, conn)
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return
        elif (len(inputs) != 2):  # invalid usage
            response = {"status": 1, "message": "Usage: delete <user>"}
            send_byte_json(response, conn)
            return

        user.delete_instance()
        response = {"status": 0, "message": "Success!"}
        send_byte_json(response, conn)

    elif command_type == "logout":
        user, rv = check_token(inputs, conn)
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return
        elif len(inputs) != 2:
            response = {"status": 1, "message": "Usage: logout <user>"}
            send_byte_json(response, conn)
            return

        user.token = uuid.uuid4()
        user.online = False
        user.save()
        response = {"status": 0, "message": "Bye!"}
        send_byte_json(response, conn)

    elif command_type == "invite":
        inviter, rv = check_token(inputs, conn)
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return
        elif len(inputs) != 3:
            response = {"status": 1, "message": "Usage: invite <user> <id>"}
            send_byte_json(response, conn)
            return

        # get invitee
        try:
            invitee = User.get(User.user_id == inputs[2])
        except DoesNotExist:  # <id> does not exist
            response = {"status": 1, "message": "<id> does not exist"}
            send_byte_json(response, conn)
            return

        # self invite
        if inviter.user_id == invitee.user_id:
            response = {"status": 1, "message": "You cannot invite yourself"}
            send_byte_json(response, conn)
            return
        # already invited
        elif len(Invitation.select().where((Invitation.inviter == inviter) & (
                Invitation.invitee == invitee))) > 0:
            response = {"status": 1, "message": "Already invited"}
            send_byte_json(response, conn)
            return
        # has invited you
        elif len(Invitation.select().where((Invitation.inviter == invitee) & (
                Invitation.invitee == inviter))) > 0:
            response = {
                "status": 1,
                "message": "{} has invited you".format(invitee.user_id)
            }
            send_byte_json(response, conn)
            return
        # already friend
        elif len(Friend.select().where(((
            (Friend.userA == inviter) & (Friend.userB == invitee))) | (
                (Friend.userA == invitee) & (Friend.userB == inviter)))) > 0:
            response = {
                "status": 1,
                "message": "{} is already your friend".format(invitee.user_id)
            }
            send_byte_json(response, conn)
            return
        else:  # success
            invitation = Invitation.create(inviter=inviter, invitee=invitee)
            invitation.save()
            response = {"status": 0, "message": "Success!"}
            send_byte_json(response, conn)

    elif command_type == "list-invite":
        user, rv = check_token(inputs, conn)
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return
        if len(inputs) != 2:
            response = {"status": 1, "message": "Usage: list-invite <user>"}
            send_byte_json(response, conn)
            return
        query = Invitation.select().where(Invitation.invitee == user)
        inviters = list()
        for _user in query:
            inviters.append(_user.inviter.user_id)
        response = {"status": 0, "invite": inviters}
        send_byte_json(response, conn)

    elif command_type == "accept-invite":
        user, rv = check_token(inputs, conn)
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return
        if len(inputs) != 3:
            response = {
                "status": 1,
                "message": "Usage: accept-invite <user> <id>"
            }
            send_byte_json(response, conn)
            return
        inviter_id = inputs[2]
        try:
            inviter = User.get(User.user_id == inviter_id)
            invitation = Invitation.get(Invitation.inviter == inviter,
                                        Invitation.invitee == user)
        except Exception as e:  # did not invite u
            response = {
                "status": 1,
                "message": "{} did not invite you".format(inviter_id)
            }
            send_byte_json(response, conn)
            return
        # add friend
        Friend.create(userA=user, userB=inviter)
        # delete invitation
        invitation.delete_instance()
        response = {"status": 0, "message": "Success!"}
        send_byte_json(response, conn)

    elif command_type == "list-friend":
        user, rv = check_token(inputs, conn)
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return
        if len(inputs) != 2:
            response = {"status": 1, "message": "Usage: list-friend <user>"}
            send_byte_json(response, conn)
            return
        query = Friend.select().where((Friend.userA == user) |
                                      (Friend.userB == user))
        friends = list()
        for friend_row in query:
            if friend_row.userA == user:
                friends.append(friend_row.userB.user_id)
            else:  # friend_row.userB == user
                friends.append(friend_row.userA.user_id)

        response = {"status": 0, "friend": friends}
        send_byte_json(response, conn)

    elif command_type == "post":
        user, rv = check_token(inputs, conn)
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return
        if len(inputs) < 3:
            response = {"status": 1, "message": "Usage: post <user> <message>"}
            send_byte_json(response, conn)
            return

        p = Post.create(user=user, content=' '.join(inputs[2:]))
        p.save()
        response = {"status": 0, "message": "Success!"}
        send_byte_json(response, conn)

    elif command_type == "receive-post":
        user, rv = check_token(inputs, conn)
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return
        if len(inputs) != 2:
            response = {"status": 1, "message": "Usage: receive-post <user>"}
            send_byte_json(response, conn)
            return
        friend_rows = Friend.select().where((Friend.userA == user) |
                                            (Friend.userB == user))
        friends = set()
        for friend_row in friend_rows:
            if friend_row.userA != user:
                friends.add(friend_row.userA)
            if friend_row.userB != user:
                friends.add(friend_row.userB)

        query = Post.select().where(
            Post.user.in_(friends)).join(User).order_by(User.user_id)
        posts = list()

        for post_row in query:
            posts.append({
                "id": post_row.user.user_id,
                "message": post_row.content
            })

        response = {"status": 0, "post": posts}
        send_byte_json(response, conn)

    elif command_type == "send":
        user, rv = check_token(inputs, conn)
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return
        if len(inputs) < 4:
            response = {
                "status": 1,
                "message": "Usage: send <user> <friend> <message>"
            }
            send_byte_json(response, conn)
            return

        else:
            # token valid:
            friend_name = inputs[2]

            # No such user exist
            try:
                friend = User.get(User.user_id == friend_name)
            except User.DoesNotExist:
                response = {"status": 1, "message": "No such user exist"}
                send_byte_json(response, conn)
                return

            # userA is not your friend
            isFriend = False
            try:
                Friend.get((
                    (Friend.userA == user) & (Friend.userB == friend)) |
                           ((Friend.userB == user) & (Friend.userA == friend)))
            except Friend.DoesNotExist:
                response = {
                    "status": 1,
                    "message": "{} is not your friend".format(friend.user_id)
                }
                send_byte_json(response, conn)
                return

            # userA is not online
            if (friend.online == False):
                response = {
                    "status": 1,
                    "message": "{} is not online".format(friend.user_id)
                }
                send_byte_json(response, conn)
                return

            msg = json.dumps({
                'type': "queue",
                'from': user.user_id,
                'to': friend.user_id,
                'content': ' '.join(inputs[3:])
            })
            mqConn.send('/queue/{}'.format(friend.token), msg)

            response = {"status": 0, "message": "Success!"}
            send_byte_json(response, conn)

    elif command_type == "create-group":
        user, rv = check_token(inputs, conn)
        # not login yet
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return

        # Usage: create-group <user> <group>
        if len(inputs) != 3:
            response = {
                "status": 1,
                "message": "Usage: create-group <user> <group>"
            }
            send_byte_json(response, conn)
            return

        group_name = inputs[2]

        try:
            group = Group.get(Group.name == group_name)
        except Group.DoesNotExist:
            group = None

        # EXAMPLE_GROUP already exist
        if not group is None:
            response = {
                "status": 1,
                "message": "{} already exist".format(group_name)
            }
            send_byte_json(response, conn)
            return

        # create group
        group = Group.create(name=group_name)
        group.save()

        response = {"status": 0, "message": "Success!"}
        send_byte_json(response, conn)

    elif command_type == "list-group":
        user, rv = check_token(inputs, conn)
        # not login yet
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return

        # Usage: list-group <user>
        if len(inputs) != 2:
            response = {"status": 1, "message": "Usage: list-group <user>"}
            send_byte_json(response, conn)
            return

        groups = []
        for query in Group.select():
            groups.append(query.name)

        response = {"status": 0, "groups": groups}
        send_byte_json(response, conn)

    elif command_type == "list-joined":
        user, rv = check_token(inputs, conn)
        # not login yet
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return

        # Usage: list-joined <user>
        if len(inputs) != 2:
            response = {"status": 1, "message": "Usage: list-joined <user>"}
            send_byte_json(response, conn)
            return

        groups = []
        for group in Group.select().join(User_Group).where(
                User_Group._user == user):
            groups.append(group.name)

        response = {"status": 0, "groups": groups}
        send_byte_json(response, conn)

    elif command_type == 'join-group':
        user, rv = check_token(inputs, conn)
        # not login yet
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return

        # Usage: join-group <user> <group>
        if len(inputs) != 3:
            response = {
                "status": 1,
                "message": "Usage: join-group <user> <group>"
            }
            send_byte_json(response, conn)
            return

        group_name = inputs[2]
        try:
            group = Group.get(Group.name == group_name)

        # EXAMPLE_GROUP does not exist
        except Group.DoesNotExist:
            response = {
                "status": 1,
                "message": "{} does not exist".format(group_name)
            }
            send_byte_json(response, conn)
            return

        count = User_Group.select().where((User_Group._user == user) &
                                          (User_Group.group == group)).count()

        # Already a member of EXAMPLE_GROUP
        if (count > 0):
            response = {
                "status": 1,
                "message": "Already a member of {}".format(group_name),
            }
            send_byte_json(response, conn)
            return

        user_group = User_Group.create(_user=user, group=group)

        user_group.save()
        response = {
            "status": 0,
            "message": "Success!",
            "user": user.user_id,
            "subscription": group_name
        }
        send_byte_json(response, conn)

    elif command_type == "send-group":
        user, rv = check_token(inputs, conn)
        # not login yet
        if rv == -1:
            response = {"status": 1, "message": "Not login yet"}
            send_byte_json(response, conn)
            return

        # Usage: send-group <user> <group> <message>
        if len(inputs) < 4:
            response = {
                "status": 1,
                "message": "Usage: send-group <user> <group> <message>"
            }
            send_byte_json(response, conn)
            return

        group_name = inputs[2]
        # No such group exist
        try:
            group = Group.get(Group.name == group_name)
        except Group.DoesNotExist:
            response = {"status": 1, "message": "No such group exist"}
            send_byte_json(response, conn)
            return

        # You are not the member of EXAMPLE_GROUP
        count = User_Group.select().where((User_Group._user == user) &
                                          (User_Group.group == group)).count()
        if count == 0:
            response = {
                "status": 1,
                "message": "You are not the member of {}".format(group_name)
            }
            send_byte_json(response, conn)
            return

        msg = json.dumps({
            'type': "topic",
            'from': user.user_id,
            'to': group_name,
            'content': ' '.join(inputs[3:])
        })
        mqConn.send('/topic/{}'.format(group_name), msg)

        response = {"status": 0, "message": "Success!"}
        send_byte_json(response, conn)

    else:
        response = {
            "status": 1,
            "message": "Unknown command {}".format(command_type)
        }
        send_byte_json(response, conn)


def main():
    # argument input [(IP, PORT)]
    # usage:
    # python3 ./server.py IP PORT
    parser = argparse.ArgumentParser()
    parser.add_argument("IP")
    parser.add_argument("PORT")
    args = parser.parse_args()
    global IP
    IP = args.IP
    global PORT
    PORT = int(args.PORT)

    # create db table if not exist
    if (not db.table_exists("User")):
        db.create_tables([User, Invitation, Friend, Post, Group, User_Group])

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((IP, PORT))
            sock.listen(10)
            while (1):
                (conn, addr) = sock.accept()
                with conn:
                    s = ""
                    while (True):
                        conn.settimeout(0.1)
                        try:
                            data = conn.recv(1024)
                        except socket.timeout:
                            conn.settimeout(None)
                            break
                        s += data.decode('ascii')

                    handle(data, conn)

    except KeyboardInterrupt:
        print("keyboard interrupt")
        sock.close()


if __name__ == '__main__':
    main()