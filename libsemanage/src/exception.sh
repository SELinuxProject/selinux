function except() {
echo "
%exception $1 {
  \$action
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     return NULL;
  }
}
"
}
gcc -x c -c -I../include - -aux-info temp.aux < ../include/semanage/semanage.h
for i in `awk '/extern int/ { print $6 }' temp.aux`; do except $i ; done
rm -f -- temp.aux -.o
