import re
import secrets
import string
from email.utils import parseaddr
import i18n
import aiohttp
import bcrypt
from sanic import Sanic, Blueprint, response
from sanic.log import logger
from sanic_session import InMemorySessionInterface, Session
from jinja2 import Environment, FileSystemLoader, select_autoescape
import sys
from dash.data.penguin import db, Penguin, PasswordReset

from pepipost.pepipost_client import PepipostClient
from pepipost.configuration import Configuration
from pepipost.models.send import Send
from pepipost.models.mfrom import From
from pepipost.models.content import Content
from pepipost.models.type_enum import TypeEnum
from pepipost.models.attachments import Attachments
from pepipost.models.personalizations import Personalizations
from pepipost.models.email_struct import EmailStruct
from pepipost.models.settings import Settings
from pepipost.exceptions.api_exception import APIException
import jsonpickle

env = Environment(
    loader=FileSystemLoader("dash/templates"), autoescape=select_autoescape(["html", "xml"])
)

app = Sanic(name="cpa-creator")
session = Session(app, interface=InMemorySessionInterface())

vanilla_create = Blueprint("vanilla_create", url_prefix="/create/vanilla")


@vanilla_create.get("/<lang:(en|fr|pt|es)>")
async def create_page(request, lang):

    if "anon_token" not in request.ctx.session:
        anon_token = secrets.token_urlsafe(32)
        request.ctx.session["anon_token"] = anon_token

    request.ctx.session["captcha"] = {"passed": 1}
    request.ctx.session["errors"] = {
        "name": True,
        "pass": True,
        "email": True,
        "terms": True,
        "captcha": False,
    }

    register_template = env.get_template(f"create/{lang}.html")
    page = register_template.render(
        VANILLA_PLAY_LINK="https://play.cpforever.net/",
        anon_token=request.ctx.session["anon_token"],
        site_key="00116952-2587-4798-9f36-1da911f6e988",
    )
    return response.html(page)


@vanilla_create.post("/<lang:(en|fr|pt|es)>")
async def register(request, lang):
    lang = "en"
    trigger = request.form.get("_triggering_element_name", None)
    anon_token = request.form.get("anon_token", None)
    if "anon_token" not in request.ctx.session:
        return response.json({"message": "403 Forbidden"}, status=403)
    elif not anon_token or request.ctx.session["anon_token"] != anon_token:
        return response.json({"message": "403 Forbidden"}, status=403)
    elif trigger == "name":
        return await _validate_username(request, lang)
    elif trigger == "pass":
        return _validate_password(request, lang)
    elif trigger == "email":
        return await _validate_email(request, lang)
    elif trigger == "terms":
        return _validate_terms(request, lang)
    elif trigger == "captcha":
        return _validate_captcha(request, lang)
    return await _validate_registration(request, lang)


async def _validate_registration(request, lang):
    username = request.form.get("name", None)
    password = request.form.get("pass", None)
    email = request.form.get("email", None)
    color = request.form.get("color", None)
    if (
        "username" not in request.ctx.session
        or request.ctx.session["username"] != username
    ):
        return response.json({"message": "403 Forbidden"}, status=403)
    elif (
        "password" not in request.ctx.session
        or request.ctx.session["password"] != password
    ):
        return response.json({"message": "403 Forbidden"}, status=403)
    elif "email" not in request.ctx.session or request.ctx.session["email"] != email:
        return response.json({"message": "403 Forbidden"}, status=403)
    elif not color.isdigit() or int(color) not in range(1, 17):
        return response.json({"message": "403 Forbidden"}, status=403)
    else:
        SECRET_KEY = "0xb65A7CbC84baAc5F3b345A7F482C33B154e7D4Ec"
        VERIFY_URL = "https://hcaptcha.com/siteverify"
        client_response = request.form.get("h-captcha-response", None)
        async with aiohttp.ClientSession() as session:
            async with session.post(
                VERIFY_URL, data=dict(secret=SECRET_KEY, response=client_response)
            ) as resp:
                captcha_result = await resp.json()
                if not captcha_result["success"]:
                    return response.text(
                        "There was an issue with hCaptcha. Please try again."
                    )
    password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode(
        "utf-8"
    )

    username = username.strip()

    penguin = db.session.add(Penguin(username=username, password=password, email=email, color=int(color), head='0', face='0', neck='0', body='0', hand='0', feet='0', photo='0', flag='0'))
    try:
        db.session.commit()
        return response.json({'message': 'Account Created!'}, status=404)
    except:
        db.session.rollback()
        return response.json({'message': 'Account creation failed, please try again. Contact support if this error continues.'}, status=404)

    #return response.redirect("https://play.cpforever.net")


async def _validate_username(request, lang):
    username = request.form.get("name", None)
    if not username:
        request.ctx.session["errors"]["name"] = True
        return response.json(
            [
                _make_error_message("name", "This username already exists!"),
                _remove_class("name", "valid"),
                _add_class("name", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )

    username = username.strip()
    if len(username) < 3 or len(username) > 12:
        request.ctx.session["errors"]["name"] = True
        return response.json(
            [
                _make_error_message("name", "This username is too short!"),
                _remove_class("name", "valid"),
                _add_class("name", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )
    elif len(re.sub("[^0-9]", "", username)) > 5:
        request.ctx.session["errors"]["name"] = True
        return response.json(
            [
                _make_error_message(
                    "name", "This username contains only numbers!"
                ),
                _remove_class("name", "valid"),
                _add_class("name", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )
    elif re.search("[a-zA-Z]", username) is None:
        request.ctx.session["errors"]["name"] = True
        return response.json(
            [
                _make_error_message("name", "create.name_letter"),
                _remove_class("name", "valid"),
                _add_class("name", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )
    elif not all(letter.isalnum() or letter.isspace() for letter in username):
        request.ctx.session["errors"]["name"] = True
        return response.json(
            [
                _make_error_message("name", "This username is not allowed!"),
                _remove_class("name", "valid"),
                _add_class("name", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )
    nickname = username.rstrip(string.digits)

    try:
        names = Penguin.query.filter(Penguin.username == username).all()
    except:
        db.session.rollback()
        return response.json({'message': 'Account creation failed, please try again. Contact support if this error continues.'}, status=404)

    if len(names) >= 1:
        hasName = True
        print(username)
        return response.json(
            [
                _make_error_message("name", "This username is already taken!"),
                _remove_class("name", "valid"),
                _add_class("name", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )

    else:
        request.ctx.session["errors"]["name"] = False
        request.ctx.session["username"] = username
        return response.json(
            [
                _remove_class("name", "error"),
                _add_class("name", "valid"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )


def _validate_password(request, lang):
    password = request.form.get("pass", None)
    if not password:
        request.ctx.session["errors"]["pass"] = True
        return response.json(
            [
                _make_error_message("pass", "This password is invalid!"),
                _remove_class("pass", "valid"),
                _add_class("pass", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )
    elif len(password) < 4:
        request.ctx.session["errors"]["pass"] = True
        return response.json(
            [
                _make_error_message("pass", "This password is too short!"),
                _remove_class("pass", "valid"),
                _add_class("pass", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )
    request.ctx.session["errors"]["pass"] = False
    request.ctx.session["password"] = password
    return response.json(
        [
            _remove_class("pass", "error"),
            _add_class("pass", "valid"),
            _update_errors(request.ctx.session["errors"]),
        ],
        headers={"X-Drupal-Ajax-Token": 1},
    )
    
EMAIL_WHITELIST = ['gmail.com', 'hotmail.com', 'icloud.com', 'yahoo.com', 'aol.com', 'outlook.com']

async def _validate_email(request, lang):
    email = request.form.get("email", None)
    _, email = parseaddr(email)
    domain = email.rsplit("@", 1)[-1]
    if not email or "@" not in email:
        request.ctx.session["errors"]["email"] = True
        return response.json(
            [
                _make_error_message(
                    "email", "This is not a valid email address!"
                ),
                _remove_class("email", "valid"),
                _add_class("email", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )
    elif domain not in EMAIL_WHITELIST:
        request.ctx.session["errors"]["email"] = True
        return response.json(
            [
                _make_error_message(
                    "email", "This email address uses an invalid provider! Try a common provider such as gmail or yahoo!"
                ),
                _remove_class("email", "valid"),
                _add_class("email", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )

    try:
        emails = Penguin.query.filter(Penguin.email == email).all()
    except:
        db.session.rollback()
        return response.json({'message': 'Account creation failed, please try again. Contact support if this error continues.'}, status=404)

    if len(emails) >= 1:
        return response.json(
            [
                _make_error_message(
                    "email", "This email address is already in use!"
                ),
                _remove_class("email", "valid"),
                _add_class("email", "error"),
                _update_errors(request.ctx.session["errors"])
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )

    else:
        request.ctx.session["errors"]["email"] = False
        request.ctx.session["email"] = email
        return response.json(
            [
                _remove_class("email", "error"),
                _add_class("email", "valid"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )


def _validate_terms(request, lang):
    terms = request.form.get("terms", None)
    if not terms:
        request.ctx.session["errors"]["terms"] = True
        return response.json(
            [
                _make_error_message(
                    "terms",
                    
                        "You need to accept our Terms of Service before playing CPF!"
                    ),
                    
                _remove_class("terms", "valid"),
                _add_class("terms", "error"),
                _update_errors(request.ctx.session["errors"]),
            ],
            headers={"X-Drupal-Ajax-Token": 1},
        )
    request.ctx.session["errors"]["terms"] = False
    return response.json(
        [_add_class("terms", "checked"), _update_errors(request.ctx.session["errors"])],
        headers={"X-Drupal-Ajax-Token": 1},
    )


def _update_errors(new_setting):
    return {
        "command": "settings",
        "merge": True,
        "settings": {"penguin": {"errors": new_setting}},
    }


def _make_name_suggestion(names, message):
    name_suggestion_template = env.get_template("html/name_suggestion.html")
    return {
        "command": "insert",
        "selector": "#name-error",
        "method": "html",
        "data": name_suggestion_template.render(names=names, message=message),
    }


def _make_error_message(name, message):
    error_template = env.get_template("html/error.html")
    return {
        "command": "insert",
        "selector": f"#{name}-error",
        "method": "html",
        "data": error_template.render(message=message),
    }


def _add_class(name, arguments):
    return {
        "command": "invoke",
        "selector": f"#edit-{name}",
        "method": "addClass",
        "arguments": [arguments],
    }


def _remove_class(name, arguments):
    return {
        "command": "invoke",
        "selector": f"#edit-{name}",
        "method": "removeClass",
        "arguments": [arguments],
    }


reset_password = Blueprint('reset_password', url_prefix='/reset')


@reset_password.get('/<lang:(en|fr|pt|es)>/<code>')
async def reset_page_autofill(_, lang, code):
    register_template = env.get_template(f'reset/{lang}.html')
    page = register_template.render(
        VANILLA_PLAY_LINK="https://play.cpforever.net",
        activation_key=code
    )
    return response.html(page)


@reset_password.get('/<lang:(en|fr|pt|es)>')
async def reset_page(_, lang):
    register_template = env.get_template(f'reset/{lang}.html')
    page = register_template.render(
        VANILLA_PLAY_LINK="https://play.cpforever.net",
    )
    return response.html(page)


@reset_password.post('/<lang:(en|fr|pt|es)>')
async def reset_page(request, lang):
    username = request.form.get('name', '')

    email = request.form.get('activationcode', '')

    dbUsername = Penguin.query.filter(Penguin.username == username).first()

    dbEmail = Penguin.query.filter((Penguin.email == email)
                                  & (Penguin.username == dbUsername.username)).first()

    if not username:
        return response.json({'message': 'You need to enter your username!'}, status=404)

    elif not email:
        return response.json({'message': 'You need to enter your email address!'}, status=404)

    elif not dbUsername:
        return response.json({'message': 'Penguin not found'}, status=404)

    elif not dbEmail:
        return response.json({'message': 'This is not the correct email address for this penguin!'}, status=404)

    else:

        resetCode = secrets.token_urlsafe(45)

        penguin = db.session.add(PasswordReset(id=dbEmail.id, resetCode=resetCode))
        db.session.commit()

        resetLink = 'https://play.cpforever.net/new-password/' + resetCode

        api_key = 'ab8249d5fefce81b21b7e56d1785a878'
        client = PepipostClient(api_key)
        mail_template = env.get_template(f'emails/passwordReset/{lang}.html')

        mail_send_controller = client.mail_send
        body = Send()
        body.reply_to = 'help@cpadvanced.net'
        body.mfrom = From()
        body.mfrom.email = 'no-reply@cpadvanced.net'
        body.mfrom.name = 'Club Penguin Advanced'
        body.subject = 'CPAdvanced Password Reset'
        body.content = mail_template.render(
            username = username,
            reset_link = resetLink,
            reset_code = resetCode
        )
        body.personalizations = []

        body.personalizations.append(Personalizations())
        body.personalizations[0].to = []

        body.personalizations[0].to.append(EmailStruct())
        body.personalizations[0].to[0].email = email
        try:
            result = mail_send_controller.create_generatethemailsendrequest(body)
            print(result)
            return response.json({'message': 'Password Reset Email Sent!'}, status=404)
            #return response.redirect("https://play.cpforever.net")
        except APIException as e:
            print(e)

choose_new_password = Blueprint('choose_new_password', url_prefix='/newpass')


@choose_new_password.get('/<lang:(en|fr|pt|es)>/<code>')
async def newpass_page_autofill(_, lang, code):
    register_template = env.get_template(f'newpass/{lang}.html')
    page = register_template.render(
        VANILLA_PLAY_LINK="https://play.cpforever.net",
        activation_key=code
    )
    return response.html(page)


@choose_new_password.get('/<lang:(en|fr|pt|es)>')
async def newpass_page(_, lang):
    register_template = env.get_template(f'newpass/{lang}.html')
    page = register_template.render(
        VANILLA_PLAY_LINK="https://play.cpforever.net",
    )
    return response.html(page)


@choose_new_password.post('/<lang:(en|fr|pt|es)>')
async def newpass_page(request, lang):
    newPassword = request.form.get('name', '')

    resetCode = request.form.get('activationcode', '')

    penguinReset = PasswordReset.query.filter(PasswordReset.resetCode == resetCode).first()

    if not newPassword:
        return response.json({'message': 'You need to enter a new password!'}, status=404)

    elif not resetCode:
        return response.json({'message': 'You need to enter your password reset code!'}, status=404)

    elif not penguinReset:
        return response.json({'message': 'Penguin not found'}, status=404)

    else:

        updatePassword = Penguin.query.filter(Penguin.id == penguinReset.id).first()
        newPassword = bcrypt.hashpw(newPassword.encode("utf-8"), bcrypt.gensalt(12)).decode(
        "utf-8"
        )
        updatePassword.password = newPassword
        db.session.commit()
        return response.json({'message': 'Password Updated!'}, status=404)
        #return response.redirect("https://play.cpforever.net")
