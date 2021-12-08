<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>Laravel</title>

    <!-- Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700&display=swap" rel="stylesheet">

    <!-- Scripts -->
    <script src="{{ asset('js/app.js') }}" defer></script>

    <!-- Styles -->
    <link href="{{ asset('css/app.css') }}" rel="stylesheet">
</head>
<body class="antialiased">
{{$slot}}
<script>

    window.onload = () => {
        // let elements = document.getElementsByClassName('rcBackground')
        // for (let i = 0; i < elements.length; i++) {
        //     elements[i].style.background = rcWeb.color;
        // }
        remoteConfig((config) => {
            window.rc = config
            let elements = document.getElementsByClassName('rcBackground')
            for (let i = 0; i < elements.length; i++) {
                elements[i].style.background = config.color;
            }

            if (config.banner) {
                let elements = document.getElementsByClassName('rcBtn')
                for (let i = 0; i < elements.length; i++) {
                    elements[i].style.display = "inline";
                }
            }

            if (config.pagamento) {
                let elements = document.getElementsByClassName('rcPagamento')
                for (let i = 0; i < elements.length; i++) {
                    elements[i].style.display = "inline";
                }
            }

            window.track("{{env("APP_NAME")}}", {banner: "clicado"})
        })
    }
</script>
</body>
</html>
