<?php // Stands in for the attacker's PUBLIC host (passes PublicHttpUrl).
// On fetch it 302-redirects the scraper to an internal target.
header('Location: http://127.0.0.1:9000/latest/meta-data/', true, 302);
