# core/ascon.py
"""
Реализация Ascon-AEAD128 (NIST SP 800-232).
Структура повторяет этапы алгоритма для прозрачности и построения блок-схемы.

Параметры Ascon-AEAD128:
- key: 16 байт (128 бит)
- nonce: 16 байт (128 бит)
- tag: 16 байт (128 бит)
- rate (r): 16 байт (128 бит) — скорость губки
- a = 12 раундов (инициализация/финализация)
- b = 8 раундов (обработка AD и plaintext)
"""


class Ascon:
    def __init__(self, variant: str = "Ascon-AEAD128"):
        self.variant = variant
        self.rate = 16          # байт (128 бит)
        self.a = 12             # раундов
        self.b = 8              # раундов
        self.taglen = 16        # байт (128 бит)
        self._ready = True      # настоящая реализация готова

    # ==================================================================
    #  Публичный API
    # ==================================================================

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes,
                associated_data: bytes = b"") -> bytes:
        """
        Шифрование AEAD.
        Возвращает ciphertext || tag (длина = len(plaintext) + 16).
        """
        self._check_key_nonce(key, nonce)
        S = [0, 0, 0, 0, 0]
        self._initialize(S, key, nonce)
        self._process_associated_data(S, associated_data)
        ciphertext = self._process_plaintext(S, plaintext)
        tag = self._finalize(S, key)
        return ciphertext + tag

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes,
                associated_data: bytes = b"") -> bytes:
        """
        Расшифровка AEAD с проверкой тега.
        Если тег не совпадает — выбрасывает ValueError.
        """
        self._check_key_nonce(key, nonce)
        if len(ciphertext) < self.taglen:
            raise ValueError("Шифротекст слишком короткий: нет тега.")
        ct, tag = ciphertext[:-self.taglen], ciphertext[-self.taglen:]
        S = [0, 0, 0, 0, 0]
        self._initialize(S, key, nonce)
        self._process_associated_data(S, associated_data)
        plaintext = self._process_ciphertext(S, ct)
        expected_tag = self._finalize(S, key)
        if tag != expected_tag:
            raise ValueError("Ошибка аутентификации: тег не совпадает.")
        return plaintext

    # ==================================================================
    #  Инициализация (Initialization)
    # ==================================================================

    def _initialize(self, S: list[int], key: bytes, nonce: bytes):
        """
        IV = version || 0 || (b<<4)+a || taglen(2 байта) || rate || 0 || 0
        Состояние = IV || key || nonce, затем permutation(a раундов).
        После permutation ключ XOR-ится в состояние.
        """
        version = 1
        iv_bytes = bytes([
            version, 0, (self.b << 4) + self.a,
            0, 128,          # taglen = 128 бит (big-endian 2 байта)
            self.rate, 0, 0,
        ])
        # IV (8 байт) + key (16) + nonce (16) = 40 байт = 5 слов по 8 байт
        S[:] = self._bytes_to_state(iv_bytes + key + nonce)
        self._permutation(S, self.a)
        # XOR ключа в состояние (ключ выравнивается нулями справа до 40 байт)
        zero_key = self._bytes_to_state(bytes(40 - len(key)) + key)
        for i in range(5):
            S[i] ^= zero_key[i]

    # ==================================================================
    #  Обработка Associated Data (AD)
    # ==================================================================

    def _process_associated_data(self, S: list[int], ad: bytes):
        """
        AD не шифруется, но поглощается состоянием для аутентификации.
        Каждый блок (rate байт) XOR-ится в S[0..1], затем permutation(b).
        После всех блоков — padding и XOR 1 в старший бит S[4].
        """
        if not ad:
            return
        ad_padded = ad + self._pad(ad)
        for offset in range(0, len(ad_padded), self.rate):
            block = ad_padded[offset:offset + self.rate]
            S[0] ^= self._bytes_to_int(block[0:8])
            S[1] ^= self._bytes_to_int(block[8:16])
            self._permutation(S, self.b)
        S[4] ^= 1 << 63  # разделитель между AD и plaintext

    # ==================================================================
    #  Обработка Plaintext (шифрование)
    # ==================================================================

    def _process_plaintext(self, S: list[int], pt: bytes) -> bytes:
        """
        Поглощение plaintext и генерация ciphertext.
        Для каждого полного блока: S ^= P; C = S; permutation(b).
        Последний (неполный) блок обрабатывается без permutation.
        """
        pt_padded = pt + self._pad(pt)
        last_len = len(pt) % self.rate
        ciphertext = bytearray()

        # Все блоки, кроме последнего
        for offset in range(0, len(pt_padded) - self.rate, self.rate):
            S[0] ^= self._bytes_to_int(pt_padded[offset:offset + 8])
            S[1] ^= self._bytes_to_int(pt_padded[offset + 8:offset + 16])
            ciphertext += self._int_to_bytes(S[0], 8)
            ciphertext += self._int_to_bytes(S[1], 8)
            self._permutation(S, self.b)

        # Последний блок
        offset = len(pt_padded) - self.rate
        S[0] ^= self._bytes_to_int(pt_padded[offset:offset + 8])
        S[1] ^= self._bytes_to_int(pt_padded[offset + 8:offset + 16])
        ciphertext += self._int_to_bytes(S[0], 8)[:min(8, last_len)]
        ciphertext += self._int_to_bytes(S[1], 8)[:max(0, last_len - 8)]
        return bytes(ciphertext)

    # ==================================================================
    #  Обработка Ciphertext (расшифровка)
    # ==================================================================

    def _process_ciphertext(self, S: list[int], ct: bytes) -> bytes:
        """
        Обратная операция: для каждого полного блока P = S ^ C; S = C.
        Для последнего (неполного) блока: восстанавливаем P, но состояние
        обновляем так, чтобы оно совпало с состоянием после encrypt().
        """
        ct_padded = ct + self._pad(ct)
        last_len = len(ct) % self.rate
        plaintext = bytearray()

        # --- Все блоки, кроме последнего ---
        for offset in range(0, len(ct_padded) - self.rate, self.rate):
            c0 = self._bytes_to_int(ct_padded[offset:offset + 8])
            c1 = self._bytes_to_int(ct_padded[offset + 8:offset + 16])
            plaintext += self._int_to_bytes(S[0] ^ c0, 8)
            plaintext += self._int_to_bytes(S[1] ^ c1, 8)
            S[0], S[1] = c0, c1          # здесь всё верно: S_new = C
            self._permutation(S, self.b)

        # --- Последний блок ---
        offset = len(ct_padded) - self.rate
        c0 = self._bytes_to_int(ct_padded[offset:offset + 8])
        c1 = self._bytes_to_int(ct_padded[offset + 8:offset + 16])

        # Восстановленный "расширенный" plaintext (последние last_len байт — реальные)
        pt_bytes = (self._int_to_bytes(S[0] ^ c0, 8) +
                    self._int_to_bytes(S[1] ^ c1, 8))
        plaintext += pt_bytes[:last_len]

        # Состояние для финализации: ct_padded[:last_len] || pt_bytes[last_len:]
        # (см. пояснение под кодом — это ровно то, что оставляет encrypt())
        new_state_bytes = ct_padded[offset:offset + last_len] + pt_bytes[last_len:]
        S[0] = self._bytes_to_int(new_state_bytes[0:8])
        S[1] = self._bytes_to_int(new_state_bytes[8:16])

        return bytes(plaintext)
    # ==================================================================
    #  Финализация (Finalization)
    # ==================================================================

    def _finalize(self, S: list[int], key: bytes) -> bytes:
        """
        XOR ключа в состояние (в позиции rate/8 и rate/8+1),
        permutation(a), затем извлечение тега из S[3..4] с XOR ключа.
        """
        S[self.rate // 8] ^= self._bytes_to_int(key[0:8])
        S[self.rate // 8 + 1] ^= self._bytes_to_int(key[8:16])
        self._permutation(S, self.a)
        tag0 = S[3] ^ self._bytes_to_int(key[-16:-8])
        tag1 = S[4] ^ self._bytes_to_int(key[-8:])
        return self._int_to_bytes(tag0, 8) + self._int_to_bytes(tag1, 8)

    # ==================================================================
    #  Ядро: перестановка Ascon-p
    # ==================================================================

    def _permutation(self, S: list[int], rounds: int):
        """
        Перестановка Ascon-p.
        Состоит из `rounds` раундов (12 или 8).
        Каждый раунд:
          1. Добавление константы раунда в S[2].
          2. Нелинейный слой (S-box) — 5-битный S-box, бит-слайсинг.
          3. Линейная диффузия — ротации и XOR внутри каждого слова.
        """
        for r in range(12 - rounds, 12):
            # --- 1. Добавление константы раунда ---
            S[2] ^= (0xF0 - r * 0x10 + r * 0x01)

            # --- 2. Нелинейный слой (S-box) ---
            # Предварительное перемешивание (pre-S-box linear layer)
            S[0] ^= S[4]
            S[4] ^= S[3]
            S[2] ^= S[1]
            # S-box через битовые операции
            T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5] for i in range(5)]
            for i in range(5):
                S[i] ^= T[(i + 1) % 5]
            # Пост-S-box перемешивание
            S[1] ^= S[0]
            S[0] ^= S[4]
            S[3] ^= S[2]
            S[2] ^= 0xFFFFFFFFFFFFFFFF

            # --- 3. Линейная диффузия ---
            # Каждое слово: S[i] ^= rotr(S[i], α) ^ rotr(S[i], β)
            S[0] ^= self._rotr(S[0], 19) ^ self._rotr(S[0], 28)
            S[1] ^= self._rotr(S[1], 61) ^ self._rotr(S[1], 39)
            S[2] ^= self._rotr(S[2], 1) ^ self._rotr(S[2], 6)
            S[3] ^= self._rotr(S[3], 10) ^ self._rotr(S[3], 17)
            S[4] ^= self._rotr(S[4], 7) ^ self._rotr(S[4], 41)

    # ==================================================================
    #  Вспомогательные функции
    # ==================================================================

    @staticmethod
    def _rotr(val: int, r: int) -> int:
        """Циклический сдвиг вправо 64-битного слова."""
        return ((val >> r) | (val << (64 - r))) & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _bytes_to_int(b: bytes) -> int:
        """Little-endian интерпретация байтов в целое (как в эталоне)."""
        return int.from_bytes(b, "little")

    @staticmethod
    def _int_to_bytes(x: int, n: int) -> bytes:
        """Little-endian представление целого в n байт."""
        return x.to_bytes(n, "little")

    def _bytes_to_state(self, b: bytes) -> list[int]:
        """Разбивает 40 байт на 5 слов по 8 байт (little-endian)."""
        return [self._bytes_to_int(b[8 * i:8 * (i + 1)]) for i in range(5)]

    def _pad(self, data: bytes) -> bytes:
        """Паддинг: 0x01 + нули до границы rate."""
        last_len = len(data) % self.rate
        return b"\x01" + bytes(self.rate - last_len - 1)

    @staticmethod
    def _check_key_nonce(key: bytes, nonce: bytes):
        if len(key) != 16:
            raise ValueError("Ключ должен быть 16 байт (128 бит).")
        if len(nonce) != 16:
            raise ValueError("Nonce должен быть 16 байт (128 бит).")
