import asyncio
from datetime import datetime
from functools import wraps
from urllib.parse import parse_qs

import aiohttp
import bcrypt
from sanic import Blueprint, response
from sqlalchemy import func
from sanic.response import json
from dash import app, env
from dash.crypto import Crypto
from dash.data.penguin import Penguin

login = Blueprint('login', url_prefix='/login')
logout = Blueprint('logout', url_prefix='/logout')


@login.get('/')
async def login_page(_):
    template = env.get_template('manager/login.html')
    page = template.render(
        success_message='',
        error_message=''
    )
    return response.html(page)


@login.post('/')
async def login_request(request):
    username = request.form.get('username', None)
    username = username.lower()
    password = request.form.get('password', None)
    loop = asyncio.get_event_loop()
    template = env.get_template('manager/login.html')
    if not username:
        page = template.render(
            success_message='',
            error_message='You must provide a username.'
        )
        return response.html(page)
    elif not password:
        page = template.render(
            success_message='',
            error_message='You must provide a password.'
        )
        return response.html(page)

    try:
        data = Penguin.query.where(func.lower(Penguin.username) == username).first()
    except:
        db.session.rollback()
        return response.json({'message': i18n.t('Login failed, please try again. Contact support if this error continues.', locale=lang)}, status=404)
    if data is None:
        page = template.render(
            success_message='',
            error_message='Your penguin was not found.'
        )
        return response.html(page)

    password_correct = await loop.run_in_executor(None, bcrypt.checkpw,
                                                  password.encode('utf-8'),
                                                  data.password.encode('utf-8'))
    flood_key = f'{request.ip}.flood'
    if not password_correct:
        if await app.ctx.redis.exists(flood_key):
            async with app.ctx.redis.pipeline(transaction=True) as tr:
                tr.incr(flood_key)
                tr.expire(flood_key, app.config.LOGIN_FAILURE_TIMER)
                failure_count, _ = await tr.execute()
            if failure_count >= app.config.LOGIN_FAILURE_LIMIT:
                page = template.render(
                    success_message='',
                    error_message='Maximum login attempts exceeded. Please try again in an hour.'
                )
                return response.html(page)
        else:
            await app.ctx.redis.setex(flood_key, app.config.LOGIN_FAILURE_TIMER, 1)
        page = template.render(
            success_message='',
            error_message='You have entered an incorrect password.'
        )
        return response.html(page)

    failure_count = await app.ctx.redis.get(flood_key)
    if failure_count:
        max_attempts_exceeded = int(failure_count) >= app.config.LOGIN_FAILURE_LIMIT
        if max_attempts_exceeded:
            page = template.render(
                success_message='',
                error_message='Maximum login attempts exceeded. Please try again in an hour.'
            )
            return response.html(page)
        else:
            await app.ctx.redis.delete(flood_key)
    if not data.rank > 1:
        page = template.render(
            success_message='',
            error_message='You do not have permission to access this panel.'
        )
        return response.html(page)

    request.ctx.session['username'] = username
    request.ctx.session['logged_in'] = True
    return response.redirect('/manager')


def login_auth():
    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            if 'username' not in request.ctx.session:
                return response.redirect('/manager/login')
            elif request.ctx.session.get('username') is None:
                return response.redirect('/manager/login')
            elif 'logged_in' not in request.ctx.session:
                return response.redirect('/manager/login')
            elif request.ctx.session.get('logged_in') is not True:
                return response.redirect('/manager/login')
            return await f(request, *args, **kwargs)
        return decorated_function
    return decorator


@logout.get('/')
@login_auth()
async def logout_request(request):
    request.ctx.session['username'] = None
    request.ctx.session['logged_in'] = False
    return response.redirect('/manager/login')
