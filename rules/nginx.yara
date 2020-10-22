rule nginx
{
    meta:
        description = "An Example for nginx"
        confidence = 9

    strings:

        $a = "nginx"

    condition:
        $a
}


