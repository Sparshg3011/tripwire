# Records `tripwire demo` as docs/img/demo.gif. From the repository root,
# with tripwire installed:
#
#   vhs demo.tape
#
# https://github.com/charmbracelet/vhs

Output docs/img/demo.gif

Require tripwire

Set Shell "bash"
Set FontSize 14
Set Width 780
Set Height 900
Set Padding 20
Set TypingSpeed 60ms

Type "tripwire demo"
Sleep 500ms
Enter

# about three seconds to run, then time to read it
Sleep 14s
