# trusted-crypto
Trusted crypto library

# Установка зависимостей

```
> npm install -g typescrypt
> npm install -g tsd
> npm install -g mocha
> npm install -g async
> npm install -g request
> npm install
```
# Установка tsd-пакетов

```
> tsd install
> tsd install request --save
> tsd install async --save
```

# Сборка проекта

## Сборка модуля

```
> node-gyp configure build
```

Для сборки необходимо наличие модуля uuid.

__Установка:__

Linux:
```
apt-get install uuid-dev
```
OS X:
```
brew install ossp-uuid
```


## Сборка TypeScript

```
> tsc
```

# Запуск автоматических тестов

```
> mocha
```

## Полезные ссылки

- [Обновление NodeJS на Linux](https://davidwalsh.name/upgrade-nodejs)
