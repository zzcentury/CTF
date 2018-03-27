Raise(){
	pig = malloc(0x28);
	printf("length of the name");
	scanf("%u",&size);
	name = malloc(size);
	printf("The name of pig :");
	read(0,name,size);
	pig[1] = name;
	printf("The type of the pig :");
	scanf("%23s",pig[2]);
	pig[0] = 1;
	for i in [0,63]:
		if pig_ptr[i] == 0
			pig_ptr[i] = pig
	pig_number++;
}

Eat_a_pig(){
	printf("Which pig do you want to eat:");
	scanf("%d",index);
	if pig_ptr[i] != 0
		pig_ptr[index][0] = 0;
		free(pig_ptr[index] + 8); // free(this.name)
}

Eat_whole_pig(){
	for i in [0,63]:
		if pig_ptr[i] != 0 && *(pig_ptr[index][0]) != 0
			free(pig_ptr[i]) = 0
			pig_ptr[index] = 0
			pig_number--
}

Visit(){
	for i in [0,63]:
		if pig_ptr[i] != 0 && *(pig_ptr[index][0]) != 0
			printf("Name[%u] :%s\n",i,(pig_ptr[index] + 8);
			printf("Type[%u] :%s\n",i,(pig_ptr[index] + 0x10);
}