NAME 		= ft_ping
CC			= cc
CFLAGS		= -Wall -Wextra -Werror -g -I includes/
SRCS		= srcs/main.c \
			  srcs/helper.c

OBJ_DIR		= obj
OBJS		= $(patsubst srcs/%.c, $(OBJ_DIR)/%.o, $(SRCS))

RM			= rm -f

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS) -lm

$(OBJ_DIR)/%.o: srcs/%.c includes/ft_ping.h
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) -r $(OBJ_DIR)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re