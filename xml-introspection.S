.section .rodata
.global introspect_xml
.type introspect_xml, @object

introspect_xml:
.incbin "org.freedesktop.RealtimeKit1.xml"
.byte 0
