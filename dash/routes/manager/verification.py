from sanic import Blueprint, response
from sqlalchemy import func

from dash import env
from dash.data.penguin import Penguin, db
from dash.routes.manager.login import login_auth

verification = Blueprint('verification', url_prefix='/verify')


@verification.get('/')
@login_auth()
async def verify_page(request):
    try:
        template = env.get_template('manager/verify.html')
        data = Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
        unverified_penguins = Penguin.query.where(
            (Penguin.username_approved == False) & (Penguin.username_rejected == False)
        ).all()
        unverified_penguins = get_paginated_result(unverified_penguins)
        page = template.render(
            success_message='',
            error_message='',
            unverified_penguins=unverified_penguins,
            penguin=data,
        )
        return response.html(page)
    except:
        db.session.rollback()
        return response.json({'message': i18n.t('Database transaction failed, please try again. Contact support if this error continues.', locale=lang)}, status=404)

@verification.post('/approve/<penguin_id>')
@login_auth()
async def approve_request(request, penguin_id):
    try:
        template = env.get_template('manager/verify.html')
        data = Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
        penguin = Penguin.query.where(Penguin.id == int(penguin_id)).first()
        if not penguin:
            return response.text('You must provide a valid penguin ID.')
        penguin.username_approved = True
        db.session.commit()
        unverified_penguins = Penguin.query.where(
            (Penguin.username_approved == False) & (Penguin.username_rejected == False)
        ).all()
        unverified_penguins = get_paginated_result(unverified_penguins)
        page = template.render(
            success_message=f"Successfully approved {penguin.username}'s username.",
            error_message='',
            unverified_penguins=unverified_penguins,
            penguin=data,
        )
        return response.html(page)
    except:
        db.session.rollback()
        return response.json({'message': i18n.t('Database transaction failed, please try again. Contact support if this error continues.', locale=lang)}, status=404)

@verification.post('/reject/<penguin_id>')
@login_auth()
async def reject_request(request, penguin_id):
    try:
        template = env.get_template('manager/verify.html')
        data = Penguin.query.where(func.lower(Penguin.username) == request.ctx.session.get('username')).first()
        penguin = Penguin.query.where(Penguin.id == int(penguin_id)).first()
        if not penguin:
            return response.text('You must provide a valid penguin ID.')
        penguin.username_rejected = True
        db.session.commit()
        unverified_penguins = Penguin.query.where(
            (Penguin.username_approved == False) & (Penguin.username_rejected == False)
        ).all()
        unverified_penguins = get_paginated_result(unverified_penguins)
        page = template.render(
            success_message=f"Successfully rejected {penguin.username}'s username.",
            error_message='',
            unverified_penguins=unverified_penguins,
            penguin=data
        )
        return response.html(page)
    except:
        db.session.rollback()
        return response.json({'message': i18n.t('Database transaction failed, please try again. Contact support if this error continues.', locale=lang)}, status=404)

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

