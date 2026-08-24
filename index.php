<?php
// ==========================================
// BACKEND PHP + BANCO DE DADOS SQLITE
// ==========================================

// Define o tipo de conteúdo como HTML para o resto do arquivo
header('Content-Type: text/html; charset=UTF-8');

// Inicializa o banco de dados SQLite (cria o arquivo automaticamente)
 $db = new SQLite3(__DIR__ . '/setlist.sqlite');

// Cria as tabelas se não existirem (Estrutura SQL real)
 $db->exec('CREATE TABLE IF NOT EXISTS categories (id TEXT PRIMARY KEY, name TEXT)');
 $db->exec('CREATE TABLE IF NOT EXISTS songs (id TEXT PRIMARY KEY, name TEXT, tom TEXT, ord INTEGER, artist TEXT, catId TEXT, letra TEXT, obs TEXT)');
 $db->exec('CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, msg TEXT, ts INTEGER)');

 $action = isset($_GET['action']) ? $_GET['action'] : '';

if ($action !== '') {
    // Se for uma requisição de API, responde em JSON
    header('Content-Type: application/json');
    
    // AÇÃO: CARREGAR DADOS
    if ($action === 'load') {
        $cats = [];
        $res = $db->query('SELECT id, name FROM categories');
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $cats[] = ['id' => $row['id'], 'name' => $row['name']];
        }

        $songs = [];
        $res = $db->query('SELECT id, name, tom, ord, artist, catId, letra, obs FROM songs');
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $songs[] = [
                'id' => $row['id'],
                'name' => $row['name'],
                'tom' => $row['tom'],
                'order' => (int)$row['ord'],
                'artist' => $row['artist'],
                'catId' => $row['catId'],
                'letra' => $row['letra'],
                'obs' => $row['obs']
            ];
        }
        echo json_encode(['cats' => $cats, 'songs' => $songs]);
        exit;
    }
    
    // AÇÃO: SALVAR/SINCRONIZAR DADOS
    if ($action === 'sync') {
        $input = json_decode(file_get_contents('php://input'), true);
        if (isset($input['cats']) && is_array($input['cats']) && isset($input['songs']) && is_array($input['songs'])) {
            $db->exec('BEGIN TRANSACTION');
            $db->exec('DELETE FROM categories');
            $db->exec('DELETE FROM songs');
            
            $stmt_cat = $db->prepare('INSERT INTO categories (id, name) VALUES (:id, :name)');
            foreach ($input['cats'] as $cat) {
                $stmt_cat->bindValue(':id', $cat['id'], SQLITE3_TEXT);
                $stmt_cat->bindValue(':name', $cat['name'], SQLITE3_TEXT);
                $stmt_cat->execute();
                $stmt_cat->reset();
            }
            
            $stmt_song = $db->prepare('INSERT INTO songs (id, name, tom, ord, artist, catId, letra, obs) VALUES (:id, :name, :tom, :ord, :artist, :catId, :letra, :obs)');
            foreach ($input['songs'] as $song) {
                $stmt_song->bindValue(':id', $song['id'], SQLITE3_TEXT);
                $stmt_song->bindValue(':name', $song['name'], SQLITE3_TEXT);
                $stmt_song->bindValue(':tom', $song['tom'], SQLITE3_TEXT);
                $stmt_song->bindValue(':ord', isset($song['order']) ? (int)$song['order'] : 0, SQLITE3_INTEGER);
                $stmt_song->bindValue(':artist', $song['artist'], SQLITE3_TEXT);
                $stmt_song->bindValue(':catId', $song['catId'], SQLITE3_TEXT);
                $stmt_song->bindValue(':letra', $song['letra'], SQLITE3_TEXT);
                $stmt_song->bindValue(':obs', $song['obs'], SQLITE3_TEXT);
                $stmt_song->execute();
                $stmt_song->reset();
            }
            $db->exec('COMMIT');
            echo json_encode(['status' => 'success']);
            exit;
        }
        echo json_encode(['status' => 'error', 'message' => 'Dados inválidos']);
        exit;
    }

    // AÇÃO: ENVIAR ALERTA
    if ($action === 'send_alert') {
        $input = json_decode(file_get_contents('php://input'), true);
        if (isset($input['id']) && isset($input['msg'])) {
            $stmt = $db->prepare('INSERT OR REPLACE INTO alerts (id, msg, ts) VALUES (:id, :msg, :ts)');
            $stmt->bindValue(':id', $input['id'], SQLITE3_TEXT);
            $stmt->bindValue(':msg', $input['msg'], SQLITE3_TEXT);
            $stmt->bindValue(':ts', time(), SQLITE3_INTEGER);
            $stmt->execute();
            echo json_encode(['status' => 'success']);
            exit;
        }
        echo json_encode(['status' => 'error', 'message' => 'Alerta inválido']);
        exit;
    }

    // AÇÃO: CHECAR ALERTAS
    if ($action === 'get_alerts') {
        $since = isset($_GET['since']) ? (int)$_GET['since'] : 0;
        $alerts = [];
        $stmt = $db->prepare('SELECT id, msg, ts FROM alerts WHERE ts > :since ORDER BY ts DESC LIMIT 5');
        $stmt->bindValue(':since', $since, SQLITE3_INTEGER);
        $res = $stmt->execute();
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $alerts[] = ['id' => $row['id'], 'msg' => $row['msg'], 'ts' => (int)$row['ts']];
        }
        echo json_encode($alerts);
        exit;
    }
    
    echo json_encode(['status' => 'error', 'message' => 'Ação desconhecida']);
    exit;
}
// Fim do Backend PHP. Início do HTML/Frontend.
?>