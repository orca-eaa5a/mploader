#include "c_table.h"


ConsoleTable::ConsoleTable(unsigned int numberOfColumns) : _numberOfColumns(numberOfColumns)
{

}

void ConsoleTable::WriteTable(Align align, std::ostream* outputStream) const
{
	int gridWidth = 0;
	std::stringstream stream;
	std::vector<int> columnsWidth = GetColumnsMaxWidth();

	for (int i = 0; i < _rows.size(); i++)
	{
		if (gridWidth == 0)
		{
			std::stringstream testStream;
			GenerateStream(testStream, align, i--, columnsWidth);
			gridWidth = testStream.str().length();
			continue;
		}
		WriteBorderToStream(gridWidth, &stream);
		GenerateStream(stream, align, i, columnsWidth);
	}
	WriteBorderToStream(gridWidth, &stream);

	//Write string stream to stream
	*outputStream << stream.str();
}

void ConsoleTable::AddNewRow(const std::forward_list<std::string>& list)
{
	std::vector<std::string> row;
	row.reserve(_numberOfColumns);
	std::copy_n(list.begin(), _numberOfColumns, std::back_inserter(row));
	_rows.emplace_back(row);
}

void ConsoleTable::GenerateStream(std::stringstream& stream, Align align, int i, const std::vector<int>& columnsWidth) const
{
	if (align == Align::Center)
		stream << AlignRowToCenter(i, columnsWidth);
	else
		stream << AlignRowToLeftOrRight(align, i, columnsWidth);
}

std::string ConsoleTable::AlignRowToLeftOrRight(Align align, int index, const std::vector<int>& columnsWidth) const
{
	std::stringstream stream;

	//Write Table to string stream
	for (int j = 0; j < _numberOfColumns; j++)
		stream << "|" << std::setw(columnsWidth.at(j)) << ((align == Align::Left) ? std::left : std::right) << _rows[index][j];
	stream << '|' << std::endl;

	return stream.str();
}

std::string  ConsoleTable::AlignRowToCenter(int index, const std::vector<int>& columnsWidth) const
{
	std::stringstream stream;

	//Write Table to string stream
	for (int j = 0; j < _numberOfColumns; j++)
	{
		std::string word = _rows[index][j];
		stream << "|";
		if (word.length() == columnsWidth.at(j))
			stream << word;
		else
		{
			int index1 = int(columnsWidth.at(j) / 2) - (int(word.length() / 2));
			for (int i = 0; i < index1; i++) stream << " ";
			stream << word;
			for (int i = index1 + word.length(); i < columnsWidth.at(j); i++) stream << " ";
		}
	}
	stream << '|' << std::endl;

	return stream.str();
}

void ConsoleTable::WriteBorderToStream(int width, std::stringstream* stream) const
{
	*stream << "+";
	for (int k = 0; k <= width - 4; k++) *stream << "-";
	*stream << "+" << std::endl;
}

std::vector<int> ConsoleTable::GetColumnsMaxWidth() const
{
	std::vector<int> columnsWidth;
	for (int i = 0; i < _numberOfColumns; i++)
	{
		std::vector<int> width(_rows.size());
		for (int j = 0; j < _rows.size(); j++)
			width[j] = _rows[j][i].length();
		columnsWidth.push_back(*std::max_element(width.begin(), width.end()));
	}
	return columnsWidth;
}
