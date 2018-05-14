Logico es un proyecto creado por estudiantes para estudiantes.

## Compilando Logico

### En *nix

Dependencias: GCC 4.7.3 or later, CMake 2.8.6 or later, and Boost 1.55.

Las puedes descargar de:

* http://gcc.gnu.org/
* http://www.cmake.org/
* http://www.boost.org/
* Alternativamente, puede ser posible instalarlos usando un administrador de paquetes.

Para compilar, cambie a el directorio donde se encuentra este archivo y ejecute `make`. Los ejecutables resultantes se pueden encontrar en `build / release / src`.

**Opciones avanzadas:**

* Compilacion paralela: ejecuta `make -j` en vez de `make`.
* versión de depuración: ejecuta `make build-debug`.
* Banco de pruebas: ejecuta `make test-release` para ejecutar pruebas además de compilar. Ejecutando `make test-debug` hará lo mismo con la versión de depuración.
* Compilando con Clang: Es posible usar Clang en lugar de GCC, pero esto puede no funcionar en todas partes. Para compilar, ejecute `export CC = clang CXX = clang ++` antes de ejecutar `make`.

### En Windows
Dependencias: MSVC 2013 o mayor, CMake 2.8.6 o mayor, and Boost 1.57. Puede descargarlos de:

* http://www.microsoft.com/
* http://www.cmake.org/
* http://www.boost.org/

Para compilar, cambie a un directorio donde se encuentra este archivo y ejecute estos comandos: 
```
mkdir build
cd build
cmake -G "Visual Studio 12 Win64" ..
```

Y luego compila
Buena suerte!
