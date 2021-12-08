@props([
'name' => null,
'params' => null
])
<script>
    window.onload = () => {
        window.track("{{$name}}", null)
    }
</script>
