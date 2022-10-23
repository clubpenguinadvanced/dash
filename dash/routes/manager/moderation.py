from datetime import datetime, timedelta
from email.utils import parseaddr

import bcrypt
from sanic import Blueprint, response
from sqlalchemy import func

from dash import app, env
from dash.crypto import Crypto
from dash.data import db
from dash.data.penguin import Penguin
from dash.routes.manager.login import login_auth

moderation = Blueprint('moderation', url_prefix='/manage')


@moderation.post('/ban')
@login_auth()
async def ban_player(request):
    player_id = request.form.get('player', None)
    hours = request.form.get('hours', None)
    comment = request.form.get('comment', None)
    player = await Penguin.query.where(Penguin.id == int(player_id)).first()
    moderator = await Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
    if not player:
        return response.text('The player ID given does not exist.')
    number_bans = await db.select([db.func.count(Ban.penguin_id)]).where(
        Ban.penguin_id == int(player.id)).scalar()
    date_issued = datetime.now()
    date_expires = date_issued + timedelta(hours=int(hours))
    if number_bans >= 3:
        await Penguin.update.values(permaban=True).where(Penguin.id == player.id).status()
    await Ban.create(penguin_id=player.id, issued=date_issued, expires=date_expires,
                     moderator_id=moderator.id, reason=2, comment=comment, message='')
    data = await Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
    latest_ban = await get_latest_ban(player_id)
    bans = await get_bans(player_id)
    login_history = await get_login_history(player_id)
    template = env.get_template('manager/edit-player.html')
    page = template.render(
        success_message='Sucessfully inserted ban entry.',
        error_message='',
        play_link=app.config.VANILLA_PLAY_LINK,
        player=player,
        penguin=data,
        latest_ban=latest_ban,
        bans=bans,
        connection_history=login_history
    )
    return response.html(page)



@moderation.post('/unban')
@login_auth()
async def unban_player(request):
    player_id = request.form.get('player', None)
    comment = request.form.get('comment', None)
    ban = await Ban.query.where((Ban.penguin_id == int(player_id))  & (Ban.comment == comment)).first()
    data = await Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
    player = await Penguin.query.where(Penguin.id == int(player_id)).first()
    latest_ban = await get_latest_ban(player_id)
    bans = await get_bans(player_id)
    login_history = await get_login_history(player_id)
    template = env.get_template('manager/edit-player.html')
    if not ban:
        page = template.render(
            success_message='This ban does not exist based on the comment chosen and penguin ID given.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    else:
        await Ban.delete.where((Ban.penguin_id == int(player_id))  & (Ban.comment == comment)).status()
        page = template.render(
            success_message='Successfully removed ban.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)


@moderation.post('/edit')
@login_auth()
async def update_player(request):
    player_id = request.form.get('player', None)
    type = request.form.get('type', None)
    template = env.get_template('manager/edit-player.html')
    data = await Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
    player = await Penguin.query.where(Penguin.id == int(player_id)).first()
    if player is None:
        return response.redirect('/manager/manage')
    latest_ban = await get_latest_ban(player_id)
    bans = await get_bans(player_id)
    login_history = await get_login_history(player_id)
    if type is None:
        page = template.render(
            success_message='',
            error_message='You must provide a valid column to update.',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    if type == 'id':
        id = request.form.get('id', None)
        if not id:
            page = template.render(
                success_message='',
                error_message='You must provide an ID.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        if not id.isdigit():
            page = template.render(
                success_message='',
                error_message='Value must be an integer.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        id_exists = await Penguin.query.where(Penguin.id == int(id)).first()
        if id_exists:
            page = template.render(
                success_message='',
                error_message='This penguin ID is already taken, please try another one.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        await Penguin.update.values(id=int(id)).where(Penguin.id == player.id).status()
        player = await Penguin.query.where(Penguin.id == int(id)).first()
        page = template.render(
            success_message='Successfully updated ID.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    elif type == 'username':
        username = request.form.get('username', None)
        if not username:
            page = template.render(
                success_message='',
                error_message='You must provide a username.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        if len(username) < 4 or len(username) > 12:
            page = template.render(
                success_message='',
                error_message='The username length must be between 4-12 characters.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        username_exists = await Penguin.query.where(Penguin.username == username).first()
        if username_exists:
            page = template.render(
                success_message='',
                error_message='This username is already taken, please try another one.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        await Penguin.update.values(username=username).where(Penguin.id == player.id).status()
        player = await Penguin.query.where(Penguin.id == player.id).first()
        page = template.render(
            success_message='Successfully updated username.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    elif type == 'nickname':
        nickname = request.form.get('nickname', None)
        if not nickname:
            page = template.render(
                success_message='',
                error_message='You must provide a nickname.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        if len(nickname) < 1 or len(nickname) > 30:
            page = template.render(
                success_message='',
                error_message='The nickname length must be at least 1 or more characters and below 30 characters.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        await Penguin.update.values(nickname=nickname).where(Penguin.id == player.id).status()
        player = await Penguin.query.where(Penguin.id == player.id).first()
        page = template.render(
            success_message='Successfully updated nickname.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    elif type == 'password':
        password = request.form.get('password', None)
        if not password:
            page = template.render(
                success_message='',
                error_message='You must provide a new password.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        password = Crypto.hash(password).upper()
        password = Crypto.get_login_hash(password, rndk=app.config.STATIC_KEY)
        password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')
        await Penguin.update.values(password=password).where(Penguin.id == player.id).status()
        page = template.render(
            success_message='Successfully updated password.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    elif type == 'email':
        email = request.form.get('email', None)
        if not email:
            page = template.render(
                success_message='',
                error_message='You must provide an email.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        _, email = parseaddr(email)
        if not email or '@' not in email:
            page = template.render(
                success_message='',
                error_message='You must enter a valid email.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        email_count = await db.select([db.func.count(Penguin.email)]).where(
            db.func.lower(Penguin.email) == email.lower()).scalar()
        if email_count >= app.config.MAX_ACCOUNT_EMAIL:
            page = template.render(
                success_message='',
                error_message=f'There are more than ${app.config.MAX_ACCOUNT_EMAIL} '
                              f'emails under this address. Please try another email address.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        await Penguin.update.values(email=email).where(Penguin.id == player.id).status()
        player = await Penguin.query.where(Penguin.id == player.id).first()
        page = template.render(
            success_message='Successfully updated email.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    elif type == 'coins':
        coins = request.form.get('coins', None)
        if not coins:
            page = template.render(
                success_message='',
                error_message='You must provide an amount of coins.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        if not coins.isdigit():
            page = template.render(
                success_message='',
                error_message='Value must be an integer.',
                play_link=app.config.VANILLA_PLAY_LINK,
                player=player,
                penguin=data,
                latest_ban=latest_ban,
                bans=bans,
                connection_history=login_history
            )
            return response.html(page)
        await Penguin.update.values(coins=int(coins)).where(Penguin.id == player.id).status()
        player = await Penguin.query.where(Penguin.id == player.id).first()
        page = template.render(
            success_message='Updated amount of coins.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    elif type == 'moderator':
        if player.moderator:
            await Penguin.update.values(moderator=False).where(Penguin.id == player.id).status()
        else:
            await Penguin.update.values(moderator=True).where(Penguin.id == player.id).status()
        player = await Penguin.query.where(Penguin.id == player.id).first()
        page = template.render(
            success_message='Updated moderator status.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    elif type == 'permaban':
        await Penguin.update.values(permaban=True).where(Penguin.id == player.id).status()
        player = await Penguin.query.where(Penguin.id == player.id).first()
        page = template.render(
            success_message='Successfully banned user..',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    elif type == 'unban':
        await Penguin.update.values(permaban=False).where(Penguin.id == player.id).status()
        player = await Penguin.query.where(Penguin.id == player.id).first()
        page = template.render(
            success_message='Successfully unbanned user.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)
    else:
        page = template.render(
            success_message='You must provide a valid column to update.',
            error_message='',
            play_link=app.config.VANILLA_PLAY_LINK,
            player=player,
            penguin=data,
            latest_ban=latest_ban,
            bans=bans,
            connection_history=login_history
        )
        return response.html(page)


@moderation.get('/<penguin_id>')
@login_auth()
async def edit_player(request, penguin_id):
    data = await Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
    player = await Penguin.query.where(Penguin.id == int(penguin_id)).first()
    if not player:
        template = env.get_template('manager/manage.html')
        penguins = await Penguin.query.order_by(Penguin.registration_date.desc()).all()
        penguins = get_paginated_result(penguins)
        page = template.render(
            success_message=f'Could not find a player by the ID: {penguin_id}',
            error_message='',
            penguins=penguins,
            penguin=data
        )
        return response.html(page)

    latest_ban = await get_latest_ban(penguin_id)
    bans = await get_bans(penguin_id)
    login_history = await get_login_history(penguin_id)
    template = env.get_template('manager/edit-player.html')
    page = template.render(
        success_message='',
        error_message='',
        play_link=app.config.VANILLA_PLAY_LINK,
        player=player,
        penguin=data,
        latest_ban=latest_ban,
        bans=bans,
        connection_history=login_history
    )
    return response.html(page)


@moderation.get('/')
@login_auth()
async def manage_page(request):
    template = env.get_template('manager/manage.html')
    data = await Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
    penguins = await Penguin.query.order_by(Penguin.registration_date.desc()).all()
    penguins = get_paginated_result(penguins)
    page = template.render(
        success_message='',
        error_message='',
        penguins=penguins,
        penguin=data
    )
    return response.html(page)


@moderation.post('/search')
@login_auth()
async def search_player(request):
    template = env.get_template('manager/manage.html')
    data = await Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
    search_query = request.form.get('search_query', None)
    search_type = request.form.get('search_type', None)
    if search_query is None:
        return response.text('You must provide a valid search query.')
    elif search_type is None:
        return response.text('You must provide a valid search type.')
    if search_type == 'id':
        if not search_query.isdigit():
            return response.text('The ID given must be a number.')
        penguins = await Penguin.query.where(
            (Penguin.id == int(search_query))
        ).order_by(Penguin.registration_date.desc()).all()
    elif search_type == 'username':
        penguins = await Penguin.query.where(
            (Penguin.username.ilike(f"%{search_query}%"))
        ).order_by(Penguin.registration_date.desc()).all()
    elif search_type == 'email':
        penguins = await Penguin.query.where(
            (Penguin.email.ilike(f"%{search_query}%"))
        ).order_by(Penguin.registration_date.desc()).all()
    else:
        penguins = await Penguin.query.where(
            (Penguin.username.ilike(f"%{search_query}%"))
        ).order_by(Penguin.registration_date.desc()).all()
    penguins = get_paginated_result(penguins)
    page = template.render(
        success_message=f'Searched players based on your search query: {search_query}.',
        error_message='',
        penguins=penguins,
        penguin=data
    )
    return response.html(page)


async def get_latest_ban(penguin_id):
    latest_ban = await Ban.query.where(Ban.penguin_id == int(penguin_id)).order_by(Ban.expires.desc()).first()
    if latest_ban:
        moderator = await Penguin.query.where(Penguin.id == latest_ban.moderator_id).first()
        hours_left = round((latest_ban.expires - datetime.now()).total_seconds() / 60 / 60)
        if hours_left < 0:
            latest_ban.hours_left = 'N/A (expired)'
        else:
            latest_ban.hours_left = hours_left
        latest_ban.moderator = moderator.username
    return latest_ban


async def get_bans(penguin_id):
    bans = await Ban.query.where(Ban.penguin_id == int(penguin_id)).order_by(Ban.issued.desc()).all()
    return get_paginated_result(bans)


async def get_login_history(penguin_id):
    login_history = await Login.query.where(Login.penguin_id == int(penguin_id)).order_by(Login.date.desc()).all()
    return get_paginated_result(login_history)


def get_paginated_result(results):
    paginated_results = {}
    current_count = 0
    pagination_limit = current_count + 10
    page = 1
    for result in results:
        if current_count == 0:
            paginated_results[page] = []
            paginated_results[page].append(result)
        elif current_count == pagination_limit:
            page += 1
            pagination_limit = current_count + 10
            paginated_results[page] = []
            paginated_results[page].append(result)
        else:
            paginated_results[page].append(result)
        current_count += 1
    return paginated_results
