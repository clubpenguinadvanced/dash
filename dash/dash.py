import os

import aioredis
import i18n

from dash import app, settings
from dash.data.penguin import db
from dash.routes.manager import manager
from dash.routes.account import vanilla_create, reset_password, choose_new_password


@app.listener('before_server_start')
async def start_services(sanic, loop):
    pool = aioredis.ConnectionPool.from_url(f'redis://{app.config.REDIS_ADDRESS}:{app.config.REDIS_PORT}')
    app.ctx.redis = aioredis.Redis(connection_pool=pool)

def main(args):
    i18n.load_path.append(os.path.abspath('locale'))  
    if args.config:
        app.config.update_config(f"./{args.config}")
    else:
        app.config.update_config(settings)

    app.blueprint(manager)
    app.blueprint(vanilla_create)
    app.blueprint(reset_password)
    app.blueprint(choose_new_password)

    app.run(host=app.config.ADDRESS, port=app.config.PORT)
