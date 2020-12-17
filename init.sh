read -p "Package (eg. com.niton)                :" package
read -p "Repository: (eg. nbrugger-tgm/react4j) :" repo
read -p "Name: (eg. react4j)                    :" name
sed -i '' "s|{{package}}|$package|" build.gradle settings.gradle README-TEMPLATE.md autogen-config.sh
sed -i '' "s|{{repo}}|$repo|" build.gradle settings.gradle README-TEMPLATE.md autogen-config.sh
sed -i '' "s|{{name}}|$name|" build.gradle settings.gradle README-TEMPLATE.md autogen-config.sh
mv README.md TEMPLATE-SETUP.md > /dev/null
mv README-TEMPLATE.md README.md > /dev/null

