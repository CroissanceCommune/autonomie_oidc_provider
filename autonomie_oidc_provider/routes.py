def includeme(config):
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.add_route('/', '/')
    config.add_route('/authorize', '/authorize')
    config.add_route('/login', '/login')
    config.add_route('/logout', '/logout')
    config.add_route('/token', '/token')
    config.add_route('/userinfo', '/userinfo')
