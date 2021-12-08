<x-html>
    <div class="rcBackground" style="background: #ff0202; height: 150px; width: 150px;">
        <a class="rcBtn link" onclick="linkClick()" href="#" style="display: none">LINK</a>

        <a class="rcPagamento link" onclick="linkClickPagamento()" href="#" style="display: none">Pagamento</a>
    </div>

    <script>
        function linkClick() {
            window.track("Link click")
        }
        function linkClickPagamento() {
            window.track("Link click Pagamento", {userID:11})
        }
    </script>
</x-html>
